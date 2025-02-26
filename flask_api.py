#!/usr/bin/env python3
# -*- coding: utf-8 -*-

##############################################################################
#                                                                            #
#  GhIDA: Ghidraaas - Ghidra as a Service                                    #
#                                                                            #
#  Copyright 2019 Andrea Marcelli and Mariano Graziano, Cisco Talos          #
#                                                                            #
#  Licensed under the Apache License, Version 2.0 (the "License");           #
#  you may not use this file except in compliance with the License.          #
#  You may obtain a copy of the License at                                   #
#                                                                            #
#      http://www.apache.org/licenses/LICENSE-2.0                            #
#                                                                            #
#  Unless required by applicable law or agreed to in writing, software       #
#  distributed under the License is distributed on an "AS IS" BASIS,         #
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  #
#  See the License for the specific language governing permissions and       #
#  limitations under the License.                                            #
#                                                                            #
##############################################################################

import asyncio
import hashlib
import json
import os
import shutil
import subprocess
import traceback
from typing import Annotated

from fastapi import FastAPI, File, UploadFile, HTTPException, Request
from fastapi.responses import JSONResponse, PlainTextResponse

import coloredlogs
import logging
log = None

app = FastAPI()

# Load configuration
with open("config/config.json") as f_in:
    j = json.load(f_in)
    SAMPLES_DIR = j['SAMPLES_DIR']
    IDA_SAMPLES_DIR = j['IDA_SAMPLES_DIR']
    GHIDRA_SCRIPT = j['GHIDRA_SCRIPT']
    GHIDRA_OUTPUT = j['GHIDRA_OUTPUT']
    GHIDRA_PROJECT = j['GHIDRA_PROJECT']
    GHIDRA_PATH = j['GHIDRA_PATH']
    GHIDRA_HEADLESS = os.path.join(GHIDRA_PATH, "support/analyzeHeadless")
    assert os.path.isfile(GHIDRA_HEADLESS) and os.access(GHIDRA_HEADLESS, os.X_OK), \
      f"Unable to find Ghidra analyzeHeadless command at {GHIDRA_HEADLESS}"


#############################################
#       UTILS                               #
#############################################

def set_logger(debug):
    """
    Set logger level and syntax
    """
    global log
    log = logging.getLogger('ghidraaas')
    if debug:
        loglevel = 'DEBUG'
    else:
        loglevel = 'INFO'
    coloredlogs.install(fmt='%(asctime)s %(levelname)s:: %(message)s',
                        datefmt='%H:%M:%S', level=loglevel, logger=log)

async def async_run_command(command):
    """
    Run a command and return the output
    """
    p = await asyncio.create_subprocess_exec(command[0], *command[1:], stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    stdout, stderr = await p.communicate()
    return stdout, stderr

def get_project_name(sha256):
    return sha256[:60]

def get_project_path(sha256, check=True):
    projname = get_project_name(sha256)
    project_path = os.path.join(GHIDRA_PROJECT, projname + ".gpr")

    if check:
        # Check if the sample has been analyzed
        if os.path.isfile(project_path):
            pass
        else:
            raise HTTPException(404, "Sample has not been analyzed")
        
    return project_path


def sha256_hash(str):
    """
    Compute the sha256 of the string
    """
    sha256_hash = hashlib.sha256()
    sha256_hash.update(str)
    return sha256_hash.hexdigest()


def server_init():
    """
    Server initialization: flask configuration, logging, etc.
    """
    # Check if SAMPLES_DIR folder is available
    if not os.path.isdir(SAMPLES_DIR):
        log.info("%s folder created" % SAMPLES_DIR)
        os.mkdir(SAMPLES_DIR)

    # Check if IDA_SAMPLES_DIR folder is available
    if not os.path.isdir(IDA_SAMPLES_DIR):
        log.info("%s folder created" % IDA_SAMPLES_DIR)
        os.mkdir(IDA_SAMPLES_DIR)

    # Check if GHIDRA_PROJECT folder is available
    if not os.path.isdir(GHIDRA_PROJECT):
        log.info("%s folder created" % GHIDRA_PROJECT)
        os.mkdir(GHIDRA_PROJECT)

    # Check if GHIDRA_OUTPUT folder exists
    if not os.path.isdir(GHIDRA_OUTPUT):
        log.info("%s folder created" % GHIDRA_OUTPUT)
        os.mkdir(GHIDRA_OUTPUT)

    # 400 MB limit
    #app.config["MAX_CONTENT_LENGTH"] = 400 * 1024 * 1024

    return


#############################################
#       GHIDRAAAS APIs                      #
#############################################

@app.get("/")
async def index():
    """
    Index page
    """
    return "Hi! This is Ghidraaas"


@app.post("/ghidra/api/analyze_sample/")
async def analyze_sample(sample: UploadFile):
    """
    Upload a sample, save it on the file system,
    and launch Ghidra analysis.
    """

    sample_content = await sample.read()
    if len(sample_content) == 0:
        raise HTTPException(status_code=500, detail="Empty file received")

    sha256 = sha256_hash(sample_content)

    sample_path = os.path.join(SAMPLES_DIR, sha256)
    with open(sample_path, "wb") as f_out:
        f_out.write(sample_content)

    if not os.path.isfile(sample_path):
        raise HTTPException(status_code=500, detail="File saving failure")

    log.debug("New sample saved (sha256: %s)" % sha256)

    # Check if the sample has been analyzed
    project_path = get_project_path(sha256, check=False)
    if not os.path.isfile(project_path):
        log.debug("Ghidra analysis started")

        # Import the sample in Ghidra and perform the analysis
        command = [GHIDRA_HEADLESS,
                    GHIDRA_PROJECT,
                    get_project_name(sha256),
                    "-import",
                    sample_path]
        stdout, stderr = await async_run_command(command)
        log.debug("Ghidra analysis completed")

    os.remove(sample_path)
    log.debug("Sample removed")
    return {"sha256": sha256}

@app.get("/ghidra/api/get_functions_list_detailed/{sha256}")
async def get_functions_list_detailed(sha256: str):
    """
    Given the sha256 of a sample, returns the list of functions.
    If the sample has not been analyzed, returns an error.
    """
    project_path = get_project_path(sha256)
    project_name = get_project_name(sha256)
    output_path = os.path.join(
        GHIDRA_OUTPUT, sha256 + "functions_list_a.json")

    command = [GHIDRA_HEADLESS,
                GHIDRA_PROJECT,
                project_name,
                "-process",
                sha256,
                "-noanalysis",
                "-scriptPath",
                GHIDRA_SCRIPT,
                "-postScript",
                "FunctionsListA.py",
                output_path,
                "-log",
                "ghidra_log.txt"]
    # Execute Ghidra plugin
    log.debug("Ghidra analysis started")
    stdout, stderr = await async_run_command(command)
    log.debug("Ghidra analysis completed")

    # Check if JSON response is available
    if os.path.isfile(output_path):
        with open(output_path) as f_in:
            return f_in.read()
    else:
        raise HTTPException(500, "FunctionsList plugin failure")

@app.get("/ghidra/api/get_functions_list/{sha256}")
async def get_functions_list(sha256: str):
    """
    Given the sha256 of a sample, returns the list of functions.
    If the sample has not been analyzed, returns an error.
    """
    project_path = get_project_path(sha256)
    project_name = get_project_name(sha256)

    output_path = os.path.join(
        GHIDRA_OUTPUT, sha256 + "functions_list.json")
    command = [GHIDRA_HEADLESS,
                GHIDRA_PROJECT,
                project_name,
                "-process",
                sha256,
                "-noanalysis",
                "-scriptPath",
                GHIDRA_SCRIPT,
                "-postScript",
                "FunctionsList.py",
                output_path,
                "-log",
                "ghidra_log.txt"]
    # Execute Ghidra plugin
    log.debug("Ghidra analysis started")
    stdout, stderr = await async_run_command(command)
    log.debug("Ghidra analysis completed")

    # Check if JSON response is available
    if os.path.isfile(output_path):
        with open(output_path) as f_in:
            return f_in.read()
    else:
        raise HTTPException(status_code=500, detail="FunctionsList plugin failure")


@app.get("/ghidra/api/get_decompiled_function/{sha256}/{offset}")
async def get_decompiled_function(sha256: str, offset: str):
    """
    Given a sha256, and an offset, returns the decompiled code of the
    function. Returns an error if the sample has not been analyzed by Ghidra,
    or if the offset does not correspond to a function
    """
    project_path = get_project_path(sha256)
    project_name = get_project_name(sha256)

    output_path = os.path.join(
        GHIDRA_OUTPUT, sha256 + "function_decompiled.json")
    # Call the DecompileFunction Ghidra plugin
    command = [GHIDRA_HEADLESS,
                GHIDRA_PROJECT,
                project_name,
                "-process",
                sha256,
                "-noanalysis",
                "-scriptPath",
                GHIDRA_SCRIPT,
                "-postScript",
                "FunctionDecompile.py",
                offset,
                output_path,
                "-log",
                "ghidra_log.txt"]
    # Execute Ghidra plugin
    log.debug("Ghidra analysis started")
    stdout, stderr = await async_run_command(command)
    log.debug("Ghidra analysis completed")

    # Check if the JSON response is available
    if os.path.isfile(output_path):
        with open(output_path) as f_in:
            return f_in.read()
    else:
        raise HTTPException(500, "FunctionDecompile plugin failure")


@app.get("/ghidra/api/analysis_terminated/{sha256}")
async def analysis_terminated(sha256: str):
    """
    Given a sha256, and an offset, remove the Ghidra project
    associated to that sample. Returns an error if the project does
    not exist.
    """
    project_path = get_project_path(sha256)
    project_folder_path = os.path.join(GHIDRA_PROJECT, sha256 + ".rep")
    os.remove(project_path)
    log.debug("Ghidra project .gpr removed")
    shutil.rmtree(project_folder_path)
    log.debug("Ghidra project folder .rep removed")
    return "Analysis terminated"

#############################################
#       ERROR HANDLING                      #
#############################################
@app.exception_handler(Exception)
async def default_exception_handler(request: Request, exc: Exception):
    return JSONResponse(
        status_code=500,
        content={"message": f"{exc}"},
    )

set_logger(True)
server_init()
