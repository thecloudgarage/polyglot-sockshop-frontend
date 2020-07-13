#!/bin/bash
git init
git remote add polyglot-sockshop-frontend https://github.com/thecloudgarage/polyglot-sockshop-frontend.git
git add .
git commit -m 'new commit 1'
git push -f polyglot-sockshop-frontend master
