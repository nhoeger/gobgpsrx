# Verwende das offizielle Golang-Image als Basis
FROM golang:1.17

# Lege den Arbeitsverzeichnis im Container fest
WORKDIR /go/src/gobgpsrx

# Kopiere den gesamten GoBGP-Code in das Arbeitsverzeichnis im Container
COPY . .

# Installiere Abhängigkeiten und baue das GoBGP-Binary
RUN go install ./...

# Setze den Befehl, der beim Ausführen des Containers ausgeführt werden soll
#COPY /pfad/zur/konfiguration/gobgp.conf /go/src/github.com/osrg/gobgp/
CMD ["/go/bin/gobgpd", "-f", "gobgp.conf"]