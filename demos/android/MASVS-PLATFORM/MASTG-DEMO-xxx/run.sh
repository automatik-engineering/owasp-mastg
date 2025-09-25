#!/bin/bash

NO_COLOR=true semgrep -c ../../../../rules/mastg-android-sensitive-data-in-notifications.yml ./MastgTest_reversed.java --text -o output.txt

NO_COLOR=true semgrep -c ../../../../rules/mastg-android-sensitive-data-in-notifications-manifest.yml ./AndroidManifest_reversed.xml --text -o output2.txt
