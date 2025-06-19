package com.google.android.gms.internal.mlkit_vision_barcode;

import androidx.datastore.core.InterfaceC1076h;
import kotlin.jvm.functions.Function2;

/* loaded from: classes2.dex */
public abstract class S6 {
    public static final /* synthetic */ int a = 0;

    public static void a(Class cls, Object obj) {
        if (obj != null) {
            return;
        }
        throw new IllegalStateException(cls.getCanonicalName() + " must be set");
    }

    public static void b(dagger.android.b bVar, String str, Class cls) {
        if (bVar == null) {
            if (!str.contains("%s")) {
                throw new IllegalArgumentException("errorMessageTemplate has no format specifiers");
            }
            if (str.indexOf("%s") != str.lastIndexOf("%s")) {
                throw new IllegalArgumentException("errorMessageTemplate has more than one format specifier");
            }
            throw new NullPointerException(str.replace("%s", String.valueOf(cls.getCanonicalName())));
        }
    }

    public static void c(Object obj) {
        if (obj == null) {
            throw new NullPointerException("Cannot return null from a non-@Nullable @Provides method");
        }
    }

    public static final Object d(InterfaceC1076h interfaceC1076h, Function2 function2, kotlin.coroutines.h hVar) {
        return interfaceC1076h.a(new androidx.datastore.preferences.core.i(function2, null), hVar);
    }
}
