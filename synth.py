import synthtool as s
import synthtool.gcp as gcp
import logging
import subprocess

logging.basicConfig(level=logging.DEBUG)
common_templates = gcp.CommonTemplates()
templates = common_templates.node_library(
  package_name="google-auth-library",
  repo_name="google/google-auth-library-nodejs"
)
s.copy(templates)
