from flask import Flask, request, jsonify
from flask_swagger_ui import get_swaggerui_blueprint
from datetime import datetime, timedelta
import pandas as pd

app = Flask(__name__)

# Load CSV data
data = pd.read_csv(r'c:/Users/Admin/Securin Submission/vulnerabilities.csv')  # Use raw string to handle backslashes

# Helper function to filter CVEs by various criteria
def filter_cves(cve_id=None, year=None, score=None, days=None):
    filtered_cves = data.copy()
    if cve_id:
        filtered_cves = filtered_cves[filtered_cves['cve_id'] == cve_id]
    if year:
        filtered_cves['published_date'] = pd.to_datetime(filtered_cves['published_date'])
        filtered_cves = filtered_cves[filtered_cves['published_date'].dt.year == year]
    if score:
        filtered_cves = filtered_cves[filtered_cves['cvss_score'] == score]
    if days:
        threshold_date = datetime.now() - timedelta(days=days)
        filtered_cves['last_modified_date'] = pd.to_datetime(filtered_cves['last_modified_date'])
        filtered_cves = filtered_cves[filtered_cves['last_modified_date'] >= threshold_date]
    return filtered_cves.to_dict(orient='records')

@app.route('/api/cves', methods=['GET'])
def get_cves():
    cve_id = request.args.get('cve_id')
    year = request.args.get('year', type=int)
    score = request.args.get('score', type=float)
    days = request.args.get('days', type=int)
    
    filtered_cves = filter_cves(cve_id, year, score, days)
    
    return jsonify(filtered_cves)

SWAGGER_URL = '/swagger'
API_URL = '/static/swagger.json'

swaggerui_blueprint = get_swaggerui_blueprint(
    SWAGGER_URL,
    API_URL,
    config={
        'app_name': "CVE API"
    }
)

app.register_blueprint(swaggerui_blueprint, url_prefix=SWAGGER_URL)

@app.route('/static/swagger.json')
def swagger_json():
    return jsonify({
        "swagger": "2.0",
        "info": {
            "title": "CVE API",
            "description": "API to filter and retrieve CVE details",
            "version": "1.0.0"
        },
        "basePath": "/api",
        "schemes": ["http"],
        "paths": {
            "/cves": {
                "get": {
                    "summary": "Get CVE details",
                    "parameters": [
                        {"name": "cve_id", "in": "query", "type": "string"},
                        {"name": "year", "in": "query", "type": "integer"},
                        {"name": "score", "in": "query", "type": "number"},
                        {"name": "days", "in": "query", "type": "integer"}
                    ],
                    "responses": {
                        "200": {
                            "description": "A list of CVEs",
                            "schema": {
                                "type": "array",
                                "items": {
                                    "type": "object"
                                }
                            }
                        }
                    }
                }
            }
        }
    })

if __name__ == '__main__':
    app.run(debug=True)
