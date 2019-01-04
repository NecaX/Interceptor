# Interceptor
Man In The Middle Toolkit

# Contenidos
* [Proyecto](#Proyecto)
* [Opciones](#Opciones)
* [Dependencias](#Dependencias)


# Proyecto
Interceptor surge como trabajo de clase para la asignatura de Seguridad en Redes cursada en la Universidad de Castilla la Mancha, concretamente en el Grado Superior de Ingeniería Informática en Albacete.

La idea fundamental de esta herramienta es facilitar los ataques Man In The Middle tradicionales y ampliar las opciones que estos nos ofrecen, mediante un script creado en python y apoyandonos sobre Scapy.

# Opciones
Las opciones que nos ofrece Interceptor son las siguientes:
* Ataques Man In The Middle clásicos: El clásico ataque para interceptar las comunicaciones entre dos puntos.
* Ataques Man In The Middle a varios objetivos: Ataque que nos ayuuda  interceptar las comunicaciones de varios objetivos con la puerta de enlace.
* Ataques Man In The Middle a toda la red: Nos permite obtener todos los paquetes que vayan desde cualquier origen hasta la puerta de enlace.
* Otros: Opciones varias que se utilizan dentro de los propios ataques y resultan de utilidad fuera de los mismos.

Por supuesto, la herramienta esta abierta a ampliaciones en su funcionalidad.

# Dependencias
La herramienta necesita los siguientes módulos para funcionar:
* Scapy: <https://github.com/secdev/scapy>
