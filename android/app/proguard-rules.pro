# spec/15 §3.2: JNI_OnLoad finds dev.yw.app.Native by name and registers its five native methods by name, so R8 keeps
# the class and those method names (AGP's default rules keep native method names; this states it for our class).
-keep class dev.yw.app.Native {
    native <methods>;
}
