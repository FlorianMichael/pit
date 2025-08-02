import de.florianmichael.baseproject.setupProject
import de.florianmichael.baseproject.configureApplication
import de.florianmichael.baseproject.configureShadedDependencies

plugins {
    id("de.florianmichael.baseproject.BaseProject")
}

setupProject()
configureApplication()

val shade = configureShadedDependencies()

dependencies {
    shade("org.fusesource.jansi:jansi:2.4.2")
}
