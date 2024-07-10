# app.py

from flask import Flask, request, jsonify
from flask_cors import CORS
from cve_search import load_cve_database, search_cves

app = Flask(__name__)
CORS(app)  # Add this line to enable CORS for the entire app

df = load_cve_database('cve_database.csv')

@app.route('/search', methods=['GET'])
def search():
    vendor = request.args.get('vendor', '').strip().lower()
    product = request.args.get('product', '').strip().lower()
    version = request.args.get('version', '').strip().lower()
    
    if not vendor or not product or not version:
        return jsonify({'error': 'Vendor, product, and version must be provided'}), 400
    
    cve_ids = search_cves(df, vendor, product, version)
    
    if cve_ids:
        return jsonify({'cve_ids': cve_ids}), 200
    else:
        return jsonify({'message': f'No CVEs found for {vendor} {product} {version}'}), 404

if __name__ == '__main__':
    app.run(debug=True)
