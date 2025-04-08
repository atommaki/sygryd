#!/usr/bin/env python3

import logging as log
import sys
import yaml
from flask import Flask, request
from flask_restx import Api, Resource, Namespace, fields
from dotenv import load_dotenv
from sqlalchemy import or_, and_, desc
from models import SessionLocal, Images, ImagesLight
from sqlalchemy.dialects import postgresql

log.basicConfig(
    level=log.INFO,
    stream=sys.stdout,
    format='[%(asctime)s] %(levelname)s: %(message)s',
)

load_dotenv()

with open("sygryd-config.yml", "r") as f:
    log.info("Reading config file: sygryd-config.yml")
    config = yaml.safe_load(f)['rest']

with open("sygryd-config.yml", "r") as f:
    log.info("Reading config file (backend): sygryd-config.yml")
    backend_config = yaml.safe_load(f)['backend']

if config['log_level']:
    log_level = getattr(log, config['log_level'], log.INFO)
    log.getLogger().setLevel(log_level)

app = Flask(__name__)
app.config.SWAGGER_UI_DOC_EXPANSION = 'list'
api = Api(app, title="Sygryd API", description="""
## Interactive API docs for Sygryd
Sygryd creates SBOMs and runs vulnerability scans for your docker images. It uses [syft](https://github.com/anchore/syft) for SBOMs and [grype](https://github.com/anchore/grype) for security scans.
**submit** a list of your images, check their **status** and **get the sbom json**...
""", doc='/')

root_ns = Namespace('', description='Endpoints to manage and scan Docker images')
api.add_namespace(root_ns)

image_model = root_ns.model('SingleImage', {
    'image': fields.String(required=True, description='A single Docker image name', example="postgres:16.8")
})

image_list_model = root_ns.model('ImageList', {
    'images': fields.List(fields.String, required=True, description='List of Docker image names', example=[
        "postgres:16.8", 
        "postgres:17.4", 
        "debian:12.10"
    ])
})


@root_ns.route('/servicestatus')
class ServiceStatus(Resource):
    def get(self):
        """Status of the Sygryd service with some basic stats."""
        DBsession = SessionLocal()
        image_count =           DBsession.query(ImagesLight).count()
        image_count_complete =  DBsession.query(ImagesLight).filter(and_(ImagesLight.sbom_timestamp != None,
                                                                         ImagesLight.vscan_timestamp != None)).count()
        image_count_failed =    DBsession.query(ImagesLight).filter(     ImagesLight.docker_pull_failed >= backend_config['docker_pull_retry_max']).count()
        image_count_no_sbom =   DBsession.query(ImagesLight).filter(and_(or_(ImagesLight.docker_pull_failed == None,
                                                                             ImagesLight.docker_pull_failed < backend_config['docker_pull_retry_max']),
                                                                        ImagesLight.sbom_timestamp == None)).count()
        image_count_no_vscan =  DBsession.query(ImagesLight).filter(and_(or_(ImagesLight.docker_pull_failed == None,
                                                                             ImagesLight.docker_pull_failed < backend_config['docker_pull_retry_max']),
                                                                        ImagesLight.vscan_timestamp == None)).count()

        latest_submit =         DBsession.query(ImagesLight).filter(ImagesLight.submitted_timestamp.isnot(None)).order_by(desc(ImagesLight.submitted_timestamp)).first()
        latest_submit_ts =      latest_submit.submitted_timestamp.isoformat() if latest_submit and latest_submit.submitted_timestamp else None

        latest_sbom =           DBsession.query(ImagesLight).filter(ImagesLight.sbom_timestamp.isnot(None)).order_by(desc(ImagesLight.sbom_timestamp)).first()
        latest_sbom_ts =        latest_sbom.sbom_timestamp.isoformat() if latest_sbom and latest_sbom.sbom_timestamp else None

        latest_vscan =          DBsession.query(ImagesLight).filter(ImagesLight.vscan_timestamp.isnot(None)).order_by(desc(ImagesLight.vscan_timestamp)).first()
        latest_vscan_ts =       latest_vscan.vscan_timestamp.isoformat() if latest_vscan and latest_vscan.vscan_timestamp else None

        latest_pull_fail =      DBsession.query(ImagesLight).filter(ImagesLight.docker_pull_failed_timestamp.isnot(None)).order_by(desc(ImagesLight.docker_pull_failed_timestamp)).first()
        latest_pull_fail_ts =   latest_pull_fail.docker_pull_failed_timestamp.isoformat() if latest_pull_fail and latest_pull_fail.docker_pull_failed_timestamp else None

        DBsession.close()

        return {
            "status": "running happily",
            "imagesInDB": {
                "total":                        image_count,
                "complete":                     image_count_complete,
                "failed":                       image_count_failed,
                "waitingForSBOM":               image_count_no_sbom,
                "waitingForVulnerabilityScan":  image_count_no_vscan,
                "latestImageSubmit":            latest_submit_ts,
                "latestSbomScan":               latest_sbom_ts,
                "latestVulnerabilityScan":      latest_vscan_ts,
                "latestDockerPullFailure":      latest_pull_fail_ts
            }
        }

@root_ns.route('/submit')
class SubmitImages(Resource):
    @root_ns.expect(image_list_model)
    @root_ns.doc(params={
        'reset-sbom':  'Optional boolean to trigger a new SBOM scan if the image was already in the DB (otherwise those images are ignored). A new SBOM always triggers a new vulnerability scan too.',
        'reset-vscan': 'Optional boolean to trigger a new vulnerability scan if the image was already in the DB (otherwise those images are ignored)',
    })
    @root_ns.response(200, 'Images processed')
    def post(self):
        """Submit one or more image names for scanning"""
        data = request.get_json()
        reset_sbom  = request.args.get("reset-sbom", '' ).lower()
        reset_vscan = request.args.get("reset-vscan", '').lower()
        added, reset, ignored = 0, 0, 0
        DBsession = SessionLocal()
        for image in data['images']:
            existing_entry = DBsession.query(ImagesLight).filter_by(image=image).first()
            if not existing_entry:
                log.debug(f'Adding: {image}')
                added += 1
                DBsession.add(ImagesLight(image=image))
                DBsession.commit()
            elif reset_sbom in ['true', 'yes'] or reset_vscan in ['true', 'yes']:
                log.debug(f'Reset: {image}')
                reset += 1
                if reset_sbom in ['true', 'yes']:
                    existing_entry.sbom_timestamp =    None
                    existing_entry.sbom_duration_sec = None
                    existing_entry.sbom_json =         None
                existing_entry.vscan_timestamp =    None
                existing_entry.vscan_duration_sec = None
                existing_entry.vscan_json =         None
                existing_entry.vscan_summary =      None
                DBsession.commit()
            else:
                log.debug(f'Ignored: {image}')
                ignored += 1

        DBsession.close()
        if added != 0:
            log.info(f"new images added: {added}")
        if reset != 0:
            log.info(f"reset images:     {reset}")
        return { 'added': added, 'reset': reset, 'ignored': ignored }

@root_ns.route('/list')
class ListImages(Resource):
    @root_ns.doc(params={
        'filter': {
            'description':  'Optional SQL-style pattern to filter image names, e.g. "%debian%"',
            'type':         'string'
        },
        'image-status': {
            'description':  'Filtering by image status',
            'type':         'string',
            'enum':         [ 'any', 'complete', 'failed', 'waitingForSBOM', 'waitingForVulnerabilityScan' ],
            'default':      'any'
        },
        'details': {
            'description':  'Optional boolean to show detailed information about the images',
            'type':         'string',
            'enum':         [ 'true', 'false' ],
            'default':      'false'
        }
    })
    def get(self):
        """Returns image names from the database"""
        name_filter     = request.args.get('filter')
        image_status    = request.args.get('image-status')
        details         = request.args.get('details','').lower()

        DBsession = SessionLocal()
        filters = []
        if name_filter:
            filters.append(ImagesLight.image.like(name_filter))

        match image_status:
            case "complete":
                filters.append(ImagesLight.sbom_timestamp != None)
                filters.append(ImagesLight.vscan_timestamp != None)
            case "failed":
                filters.append(ImagesLight.docker_pull_failed >= backend_config['docker_pull_retry_max'])
            case "waitingForSBOM":
                filters.append(ImagesLight.sbom_timestamp == None)
                filters.append(or_(ImagesLight.docker_pull_failed == None,
                                   ImagesLight.docker_pull_failed < backend_config['docker_pull_retry_max']))
            case "waitingForVulnerabilityScan":
                filters.append(ImagesLight.vscan_timestamp == None)
                filters.append(or_(ImagesLight.docker_pull_failed == None,
                                   ImagesLight.docker_pull_failed < backend_config['docker_pull_retry_max']))
            case None | "any" | "":
                pass  # No filtering by image status 
            case _:
                DBsession.close()
                return {'error': f'Unknown image-status value: {image_status}'}, 400

        readable_filters = [ f"({str(f.compile(dialect=postgresql.dialect(), compile_kwargs={'literal_binds': True}))})" for f in filters ]
        log.debug(f"DB Filter: " + " AND ".join(readable_filters))

        images = DBsession.query(ImagesLight).filter(*filters).limit(config['result_limit']+1).all()

        truncated = len(images) > config['result_limit']
        DBsession.close()
        if details in ['true', 'yes']:
            return {'images': [img.serialize() for img in images[:config['result_limit']]],
                    'truncated': truncated
            }
        else:
            return {'images': [img.image for img in images[:config['result_limit']]],
                    'truncated': truncated
            }

@root_ns.route('/get-sbom-json')
class get_sbom_json(Resource):
    @root_ns.expect(image_model)
    def post(self):
        """Gives back the SBOM Json for a single image"""
        data = request.get_json()
        image = data.get('image') if data else None

        if not image:
            return {'error': 'Missing "image" in request body'}, 400

        DBsession = SessionLocal()
        image_entry = DBsession.query(Images).filter(Images.image == image).first()
        DBsession.close()

        if image_entry and image_entry.sbom_json:
            return image_entry.sbom_json
        elif image_entry:
            return {'error': f'SBOM JSON not available for image: {image}'}, 404
        else:
            return {'error': f'Image not found: {image}'}, 404

@root_ns.route('/get-vscan-json')
class get_vscan_json(Resource):
    @root_ns.expect(image_model)
    def post(self):
        """Gives back the Vulnerability scan Json for a single image"""
        data = request.get_json()
        image = data.get('image') if data else None

        if not image:
            return {'error': 'Missing "image" in request body'}, 400

        DBsession = SessionLocal()
        image_entry = DBsession.query(Images).filter(Images.image == image).first()
        DBsession.close()

        if image_entry and image_entry.vscan_json:
            return image_entry.vscan_json
        elif image_entry:
            return {'error': f'VSCAN JSON not available for image: {image}'}, 404
        else:
            return {'error': f'Image not found: {image}'}, 404

@root_ns.route('/get-vscan-summary')
class get_vscan_summary(Resource):
    @root_ns.expect(image_model)
    def post(self):
        """Gives back a summary of the Vulnerability scan for a single image"""
        data = request.get_json()
        image = data.get('image') if data else None

        if not image:
            return {'error': 'Missing "image" in request body'}, 400

        DBsession = SessionLocal()
        image_entry = DBsession.query(ImagesLight).filter(ImagesLight.image == image).first()
        DBsession.close()

        if image_entry and image_entry.vscan_summary:
            image_entry_ser = image_entry.serialize()
            return {    "image":            image_entry_ser["image"],
                        "vscan_timestamp":  image_entry_ser["vscan_timestamp"],
                        "vscan_summary":    image_entry_ser["vscan_summary"]
            }
        elif image_entry:
            return {'error': f'VSCAN summary is not available for image: {image}'}, 404
        else:
            return {'error': f'Image not found: {image}'}, 404
 
@root_ns.route('/delete')
class delete(Resource):
    @root_ns.expect(image_list_model)
    def post(self):
        """Deletes images from the DB."""
        data = request.get_json()

        deleted, ignored = 0, 0
        DBsession = SessionLocal()
        for image in data['images']:
            existing_entry = DBsession.query(ImagesLight).filter_by(image=image).first()
            if existing_entry:
                DBsession.delete(existing_entry)
                DBsession.commit()
                deleted += 1
            else:
                ignored +=1

        DBsession.close()
        if deleted != 0:
            log.info(f"images deleted: {deleted}")

        return { 'deleted': deleted, 'ignored': ignored }

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
