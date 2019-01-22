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
import java.util.stream.Collectors

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
        val sslCertDirPath = System.getenv("CF_SYSTEM_CERT_PATH")
        if (sslCertDirPath != null) {
            val sslCertDir = Paths.get(sslCertDirPath)
            if (!Files.isDirectory(sslCertDir)) {
                logger.warn("SSL certificates directory not found")
            } else {
                Files.newDirectoryStream(sslCertDir).use {
                    it.filter { fileName -> fileName.toString().endsWith(".crt") }.forEach { fileName ->
                        val sslCertFile = sslCertDir.resolve(fileName)
                        val certs = readSslCertificates(sslCertFile)
                        if (certs != null) {
                            sslCerts[sslCertFile.toAbsolutePath()] = certs
                        }
                    }
                }
                if (sslCerts.isEmpty()) {
                    logger.warn("No SSL certificates found")
                }
            }
        }
        model["trustedCertificates"] = sslCerts

        val sslInstanceCertFilePath = System.getenv("CF_INSTANCE_CERT")
        if (sslInstanceCertFilePath != null) {
            val sslInstanceCertFile = Paths.get(sslInstanceCertFilePath)
            if (Files.exists(sslInstanceCertFile)) {
                val certs = readSslCertificates(sslInstanceCertFile)
                if (certs != null) {
                    model["instanceCertificate"] = certs
                    model["instanceGuid"] = System.getenv("CF_INSTANCE_GUID")
                    model["instanceIndex"] = System.getenv("CF_INSTANCE_INDEX")
                }
            }
        }

        return "index"
    }

    private fun readSslCertificates(file: Path): CharSequence? {
        logger.info("Reading SSL certificates: {}", file)
        val buf = StringBuilder(512)

        val sourceLines = Files.lines(file).collect(Collectors.toList())
        val singleCertLines = mutableListOf<String>()
        for (line in sourceLines) {
            singleCertLines.add(line)
            if (line.contains("END CERTIFICATE")) {
                val tmp = Files.createTempFile("certificate-", ".crt")
                try {
                    Files.write(tmp, singleCertLines)
                    val singleCert = readSingleSslCertificate(tmp)
                    if (buf.isNotEmpty()) {
                        buf.append("\n")
                    }
                    buf.append(singleCert)
                    singleCertLines.clear()
                } finally {
                    Files.delete(tmp)
                }
            }
        }

        return if (buf.isEmpty()) null else buf
    }

    private fun readSingleSslCertificate(file: Path): CharSequence {
        val cmd = listOf("openssl", "x509", "-in", file.toAbsolutePath().toString(), "-text", "-noout")
        return ProcessBuilder(cmd)
                .redirectOutput(ProcessBuilder.Redirect.PIPE)
                .redirectError(ProcessBuilder.Redirect.PIPE)
                .start()
                .apply { waitFor(10, TimeUnit.SECONDS) }
                .inputStream.bufferedReader().readText()
    }
}
