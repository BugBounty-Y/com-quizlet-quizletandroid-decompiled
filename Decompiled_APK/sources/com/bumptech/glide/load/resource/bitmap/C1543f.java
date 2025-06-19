package com.bumptech.glide.load.resource.bitmap;

import android.os.Build;
import android.os.ParcelFileDescriptor;
import java.nio.ByteBuffer;
import java.util.ArrayList;

/* renamed from: com.bumptech.glide.load.resource.bitmap.f, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1543f implements com.bumptech.glide.load.j {
    public final /* synthetic */ int a;
    public final o b;

    public /* synthetic */ C1543f(o oVar, int i) {
        this.a = i;
        this.b = oVar;
    }

    @Override // com.bumptech.glide.load.j
    public final boolean a(Object obj, com.bumptech.glide.load.h hVar) {
        switch (this.a) {
            case 0:
                return true;
            default:
                ParcelFileDescriptor parcelFileDescriptor = (ParcelFileDescriptor) obj;
                String str = Build.MANUFACTURER;
                return (!("HUAWEI".equalsIgnoreCase(str) || "HONOR".equalsIgnoreCase(str)) || parcelFileDescriptor.getStatSize() <= 536870912) && !"robolectric".equals(Build.FINGERPRINT);
        }
    }

    @Override // com.bumptech.glide.load.j
    public final com.bumptech.glide.load.engine.v b(Object obj, int i, int i2, com.bumptech.glide.load.h hVar) {
        switch (this.a) {
            case 0:
                o oVar = this.b;
                return oVar.a(new io.ktor.client.plugins.api.d((ByteBuffer) obj, oVar.d, oVar.c, 4), i, i2, hVar, o.j);
            default:
                o oVar2 = this.b;
                ArrayList arrayList = oVar2.d;
                androidx.compose.foundation.lazy.grid.m mVar = oVar2.c;
                com.quizlet.data.interactor.set.c cVar = new com.quizlet.data.interactor.set.c();
                com.bumptech.glide.util.f.c(mVar, "Argument must not be null");
                cVar.a = mVar;
                com.bumptech.glide.util.f.c(arrayList, "Argument must not be null");
                cVar.b = arrayList;
                cVar.c = new com.bumptech.glide.load.data.i((ParcelFileDescriptor) obj);
                return oVar2.a(cVar, i, i2, hVar, o.j);
        }
    }
}
