/*
 * Copyright (c) 2019 Pivotal Software, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package fr.alexandreroman.cfsslcerts

import org.slf4j.LoggerFactory
import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication
import org.springframework.stereotype.Controller
import org.springframework.web.bind.annotation.GetMapping
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths
import java.util.concurrent.TimeUnit

@SpringBootApplication
class Application

fun main(args: Array<String>) {
    runApplication<Application>(*args)
}

@Controller
class IndexController {
    private val logger = LoggerFactory.getLogger(javaClass)

    @GetMapping("/")
    fun index(model: MutableMap<String, Any>): String {
        val sslCerts = sortedMapOf<Path, CharSequence>()
        val sslCertDir = Paths.get("/etc/ssl/certs")
        if (!Files.isDirectory(sslCertDir)) {
            logger.warn("SSL certificates directory not found")
        } else {
            Files.newDirectoryStream(sslCertDir).use {
                it.filter { fileName -> fileName.toString().endsWith(".pem") }.forEach { fileName ->
                    val sslCertFile = sslCertDir.resolve(fileName)
                    sslCerts[sslCertFile.toAbsolutePath()] = readSslCertificate(sslCertFile)
                }
            }
            if (sslCerts.isEmpty()) {
                logger.warn("No SSL certificates found")
            }
        }
        model["trustedCertificates"] = sslCerts

        val sslInstanceCertFile = Paths.get("/etc/cf-instance-credentials/instance.crt")
        if (Files.exists(sslInstanceCertFile)) {
            model["instanceCertificate"] = readSslCertificate(sslInstanceCertFile)
            model["instanceGuid"] = System.getenv("CF_INSTANCE_GUID")
            model["instanceIndex"] = System.getenv("CF_INSTANCE_INDEX")
        }

        return "index"
    }

    private fun readSslCertificate(file: Path): CharSequence {
        logger.info("Reading SSL certificate: {}", file)
        val cmd = listOf("openssl", "x509", "-in", file.toAbsolutePath().toString(), "-text", "-noout")
        return ProcessBuilder(cmd)
                .redirectOutput(ProcessBuilder.Redirect.PIPE)
                .redirectError(ProcessBuilder.Redirect.PIPE)
                .start()
                .apply { waitFor(10, TimeUnit.SECONDS) }
                .inputStream.bufferedReader().readText()
    }
}
