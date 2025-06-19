package com.google.android.datatransport.cct;

import androidx.annotation.Keep;
import com.google.android.datatransport.runtime.backends.c;
import com.google.android.datatransport.runtime.backends.h;

@Keep
/* loaded from: classes2.dex */
public class CctBackendFactory {
    public h create(c cVar) {
        com.google.android.datatransport.runtime.backends.b bVar = (com.google.android.datatransport.runtime.backends.b) cVar;
        return new b(bVar.a, bVar.b, bVar.c);
    }
}
