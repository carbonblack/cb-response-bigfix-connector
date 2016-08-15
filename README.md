## Project Fletch

Integration between Cb Response and IBM Bigfix.

### Use

This integration (in its initial stages) is designed to listen to data from the cb event forwarder, process it, and then ship the data over to IBM Bigfix for showing the dashboard data.


## Notes for deploying in the Cb-BigFix Demo Roadshow, May 2016.

I) Setup the Phase II demo feed.
    1) Copy the nvd-phase2.json file into the public web folder
    sudo mkdir /var/www/cb/feeds
    sudo cp cb-bigfix-nvd-phaseII.json /var/www/cb/feeds/

    2) Add the feed into the CbR via Threat Intel page
    https://localhost/feeds/cb-bigfix-nvd-phaseII.json

II) Setup a second cb-event-forwarder instance 