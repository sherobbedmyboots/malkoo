# Create an environment variable for the correct distribution:
export CLOUD_SDK_REPO="cloud-sdk-$(lsb_release -c -s)"

# Add the Cloud SDK distribution URI as a package source:
echo "deb http://packages.cloud.google.com/apt $CLOUD_SDK_REPO main" | sudo tee -a /etc/apt/sources.list.d/google-cloud-sdk.list

# If you have apt-transport-https installed, you can use "https" instead of "http" in this step.
# Import the Google Cloud public key:
curl https://packages.cloud.google.com/apt/doc/apt-key.gpg | sudo apt-key add -

# Update and install the Cloud SDK:
sudo apt-get update && sudo apt-get install google-cloud-sdk

# additional components
sudo apt-get install google-cloud-sdk-app-engine-python

# start
gcloud init