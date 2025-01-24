FROM mcr.microsoft.com/openjdk/jdk:21-ubuntu

WORKDIR /github-actions

COPY build/libs/github-actions-0.0.1-SNAPSHOT.jar github-actions.jar

EXPOSE 9090

ENTRYPOINT ["java", "-jar", "github-actions.jar"]