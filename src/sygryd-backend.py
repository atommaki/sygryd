#!/usr/bin/env python3

import sys
import os
import re
import subprocess
import logging as log
import time
import yaml
import json
import signal
import psycopg2
import select
import docker
from datetime import datetime, timedelta, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed, wait
from models import SessionLocal, Images, ImagesLight
from models import DB_USER, DB_PASSWORD, DB_HOST, DB_PORT, DB_NAME
from dotenv import load_dotenv
from sqlalchemy import and_, or_
from collections import Counter

log.basicConfig(
    level=log.INFO,
    stream=sys.stdout,
    format='[%(asctime)s] [%(threadName)s] %(levelname)s: %(message)s'
)

load_dotenv()

with open("sygryd-config.yml", "r") as f:
    log.info("Reading config file: sygryd-config.yml")
    config = yaml.safe_load(f)['backend']

if config['log_level']:
    log_level = getattr(log, config['log_level'], log.INFO)
    log.getLogger().setLevel(log_level)

def handle_sigterm(signum, frame):
    log.info("Received SIGTERM, shutting down...")
    sys.exit(0)
signal.signal(signal.SIGTERM, handle_sigterm)

def docker_pull(image):
    dclient = docker.from_env()
    try:
        start_time = time.time()
        dclient.images.pull(image)
        duration_sec = int(time.time() - start_time)
        log.debug(f"Docker pull took {duration_sec}sec for image: {image}")
        return True
    except Exception as e:
        log.error(f"Docker pull unsuccessful for image: {image}")
        log.debug(e)
        return False

def docker_image_rm(image):
    dclient = docker.from_env()
    try:
        dclient.images.remove(image)
        return True
    except Exception as e:
        log.error(f"Docker pull unsuccessful for image: {image}")
        log.error(e)
        return False

def get_clean_image_name(image):
    return re.sub(r'\W+', '_', image)

def run_command(command, env_vars={}, output=None, output_infolog=False):
    env_string = "; ".join([f'{k}="{v}"' for k, v in env_vars.items()])
    if env_vars:
        env_string = env_string + '; '
    full_command = f'{env_string}{command}'
    log.debug(full_command)
    try:
        result = subprocess.run(
            [ 'bash', '-lc', full_command ],
            capture_output = True,
            text = True,
            check = True,
        )
        if output != None:
            try:
                with open(output, "w") as f:
                    f.write(result.stdout)
            except Exception as write_err:
                log.error(f'Error writing to file: {write_err}')

        if output_infolog:
            stdoutlog=log.info
        else:
            stdoutlog=log.debug

        if len(result.stdout.strip()) > 200:
            stdoutlog(result.stdout.strip()[:200] + '...[truncated]')
        else:
            stdoutlog(result.stdout.strip())
        log.debug(result.stderr.strip())
        log.debug('Command finished succesfully.')
        return True
    except subprocess.CalledProcessError as e:
        log.error('Command failed.')
        log.error(e.stderr.strip())
        return False

def get_vscan_summary(vscan_json):
    with open(vscan_json, "r") as f:
        data = json.load(f)
    severities = [match["vulnerability"]["severity"] for match in data.get("matches", [])]
    vscan_summary = dict(Counter(severities))
    return vscan_summary

def run_sbom_or_vscan(image, sbom_or_vscan, out_json, DBsession, DBimage, env_vars={}):
    log_msg_base=f"Creating {sbom_or_vscan.upper()} for image: {image}"
    log.info(f"[Start]    {log_msg_base}")
    start_time = time.time()
    if not run_command(config['command'][sbom_or_vscan], env_vars=env_vars, output=out_json):
        log.error(f"[Failed]  {log_msg_base}")
        return False
    duration_sec = int(time.time() - start_time)
    log.debug(f"Command was running for {duration_sec} sec.")
    log.debug(f"Updating {sbom_or_vscan.upper()} in the DB for image: {image}")
    log.debug(f"File:        {out_json}")
    log.debug(f"File size:   {os.path.getsize(out_json)}")
    try:
        with open(out_json, 'r') as f:
            json_data = json.load(f)
    except Exception as e:
        log.error(f"Failed to load {sbom_or_vscan.upper()} JSON: {e}")
        return False
    try:
        setattr(DBimage, f'{sbom_or_vscan}_timestamp',      datetime.now(timezone.utc))
        setattr(DBimage, f'{sbom_or_vscan}_json',           json_data)
        setattr(DBimage, f'{sbom_or_vscan}_duration_sec',   duration_sec)
        match sbom_or_vscan:
            case "sbom":
                # invalidate old vscan results (if there was any)
                DBimage.vscan_timestamp =    None
                DBimage.vscan_json =         None
                DBimage.vscan_duration_sec = None
            case "vscan":
                log.debug(f"Get VSCAN summary for image: {image}")
                DBimage.vscan_summary = get_vscan_summary(out_json)
                log.debug(f"VSCAN summary: {DBimage.vscan_summary}")
        DBsession.commit()
        log.info(f"[Finished] {log_msg_base}")
    except Exception as e:
        log.error(f"DB update failure: {e}")
        return False
    return True

def process_single_image(image, vscan_only):
    log.debug(f"Image processing started: {image} ({vscan_only = })")
    DBsession = SessionLocal()
    try:
        DBimage = DBsession.query(Images).filter_by(image=image).first()
        sbom_json =  get_clean_image_name(image) + "-sbom.json"
        vscan_json = get_clean_image_name(image) + "-vscan.json"
        
        ### SBOM ###
        if not vscan_only:
            if not docker_pull(image):
                docker_pull_failed_current = getattr(DBimage, 'docker_pull_failed', 0) or 0
                DBimage.docker_pull_failed = docker_pull_failed_current + 1
                DBimage.docker_pull_failed_timestamp = datetime.now(timezone.utc)
                DBsession.commit()
                return
            if not run_sbom_or_vscan(image, 'sbom', sbom_json, DBsession, DBimage, env_vars={ 'DOCKER_IMAGE': image }):
                return
            docker_image_rm(image)
        else:
            with open(sbom_json, 'w') as f:
                json.dump(DBimage.sbom_json, f, indent=2)

        ### VSCAN ###
        if config['run_vscan'] == True:
            run_sbom_or_vscan(image, 'vscan', vscan_json, DBsession, DBimage, env_vars={ 'SBOM_JSON': sbom_json })

    except:
        #log.info(f'DB Rollback! ({image})')
        #DBsession.rollback()
        raise
    finally:
        DBsession.close()
        if os.path.exists(sbom_json):  os.remove(sbom_json)
        if os.path.exists(vscan_json): os.remove(vscan_json)

def process_images(sbom_or_vscan):
    DBsession = SessionLocal()
    docker_pull_max_time = datetime.now(timezone.utc) - timedelta(minutes=config['docker_pull_retry_minutes'])
    base_conditions = [
        or_(
            ImagesLight.docker_pull_failed_timestamp == None,
            ImagesLight.docker_pull_failed_timestamp < docker_pull_max_time
        ),
        or_(
            ImagesLight.docker_pull_failed == None,
            ImagesLight.docker_pull_failed < config['docker_pull_retry_max']
        )
    ]
    try:
        match sbom_or_vscan:
            case "sbom":
                filters = [ImagesLight.sbom_timestamp == None] + base_conditions
            case "vscan":
                filters = [
                            ImagesLight.vscan_timestamp == None,
                            ImagesLight.sbom_timestamp != None
                          ] + base_conditions
            case _:
                raise ValueError(f"Unknown scan type: {sbom_json}")
            
        pending_images = DBsession.query(ImagesLight).filter(and_(*filters)).all()
        if not pending_images:
            log.debug(f"No pending images to process ({sbom_or_vscan}).")
            return
        log.debug(f"Start processing { len(pending_images) } for {sbom_or_vscan}")

        with ThreadPoolExecutor(max_workers=config['max_workers'], thread_name_prefix="Thread") as executor:
            futures = [executor.submit(process_single_image, img.image, vscan_only=sbom_or_vscan=='vscan') for img in pending_images]
            wait(futures)
    except:
        DBsession.rollback()
        raise
    finally:
        DBsession.close()


def wait_for_DB_changes(timeout):
    log.debug(f"Waiting for DB changes (timeout={timeout})...")
    dsn = f"dbname={DB_NAME} user={DB_USER} password={DB_PASSWORD} host={DB_HOST} port={DB_PORT}"
    conn = psycopg2.connect(dsn)
    conn.set_isolation_level(psycopg2.extensions.ISOLATION_LEVEL_AUTOCOMMIT)
    cur = conn.cursor()
    cur.execute("LISTEN table_changed;")
    select.select([conn], [], [], timeout)
    conn.poll()

    if conn.notifies:
        while conn.notifies:
            notify = conn.notifies.pop(0)
            log.info("DB Change detected")
        return True
    else:
        log.debug(f"Timeout ({timeout}) reached, no DB change detected")
        return False

if __name__ == "__main__":
    log.info("sygrid-backend started")
    log.info(f"Running with max { config['max_workers'] } parallel jobs.")
    run_command('syft --version',  output_infolog=True)
    run_command('grype --version', output_infolog=True)
    log.info("Updating grype vulnerability database.")
    run_command('grype db update', output_infolog=True)

    log.info("Waiting for database changes...")
    while True:
        process_images('sbom')
        if config['run_vscan'] == True:
            process_images('vscan')
        wait_for_DB_changes(timeout=config['DB_trigger_timeout'])
