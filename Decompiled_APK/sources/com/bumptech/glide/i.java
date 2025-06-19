package com.bumptech.glide;

import android.content.ContentResolver;
import android.content.Context;
import android.content.res.AssetFileDescriptor;
import android.content.res.Resources;
import android.graphics.Bitmap;
import android.graphics.drawable.BitmapDrawable;
import android.graphics.drawable.Drawable;
import android.net.Uri;
import android.os.Build;
import android.os.ParcelFileDescriptor;
import androidx.appcompat.app.L;
import androidx.compose.foundation.text.input.internal.u;
import com.bumptech.glide.integration.okhttp3.OkHttpGlideModule;
import com.bumptech.glide.load.model.A;
import com.bumptech.glide.load.model.C1533a;
import com.bumptech.glide.load.model.C1535c;
import com.bumptech.glide.load.model.C1537e;
import com.bumptech.glide.load.model.m;
import com.bumptech.glide.load.model.stream.b;
import com.bumptech.glide.load.model.stream.c;
import com.bumptech.glide.load.model.y;
import com.bumptech.glide.load.resource.bitmap.B;
import com.bumptech.glide.load.resource.bitmap.C1538a;
import com.bumptech.glide.load.resource.bitmap.C1539b;
import com.bumptech.glide.load.resource.bitmap.C1540c;
import com.bumptech.glide.load.resource.bitmap.C1543f;
import com.bumptech.glide.load.resource.bitmap.F;
import com.bumptech.glide.load.resource.bitmap.o;
import com.bumptech.glide.load.resource.bitmap.s;
import com.google.android.gms.internal.mlkit_vision_common.C;
import java.io.File;
import java.io.InputStream;
import java.net.URL;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

/* loaded from: classes.dex */
public abstract class i {
    public static h a(Glide glide, List list, C c) {
        com.bumptech.glide.load.j c1543f;
        com.bumptech.glide.load.j c1538a;
        int i;
        Resources resources;
        com.bumptech.glide.load.j jVar;
        String str;
        com.bumptech.glide.load.j jVar2;
        com.bumptech.glide.load.engine.bitmap_recycle.a aVar = glide.a;
        e eVar = glide.c;
        Context applicationContext = eVar.getApplicationContext();
        L l = eVar.h;
        h hVar = new h();
        com.bumptech.glide.load.resource.bitmap.l lVar = new com.bumptech.glide.load.resource.bitmap.l();
        com.airbnb.lottie.model.animatable.c cVar = hVar.g;
        synchronized (cVar) {
            cVar.a.add(lVar);
        }
        int i2 = Build.VERSION.SDK_INT;
        if (i2 >= 27) {
            s sVar = new s();
            com.airbnb.lottie.model.animatable.c cVar2 = hVar.g;
            synchronized (cVar2) {
                cVar2.a.add(sVar);
            }
        }
        Resources resources2 = applicationContext.getResources();
        ArrayList arrayListE = hVar.e();
        androidx.compose.foundation.lazy.grid.m mVar = glide.d;
        com.bumptech.glide.load.resource.gif.a aVar2 = new com.bumptech.glide.load.resource.gif.a(applicationContext, arrayListE, aVar, mVar);
        com.bumptech.glide.load.j f = new F(aVar, new com.quizlet.shared.usecase.srs.a(6));
        o oVar = new o(hVar.e(), resources2.getDisplayMetrics(), aVar, mVar);
        if (i2 < 28 || !((Map) l.b).containsKey(b.class)) {
            c1543f = new C1543f(oVar, 0);
            c1538a = new C1538a(2, oVar, mVar);
        } else {
            c1538a = new com.bumptech.glide.load.resource.bitmap.g(1);
            c1543f = new com.bumptech.glide.load.resource.bitmap.g(0);
        }
        if (i2 >= 28) {
            i = i2;
            resources = resources2;
            jVar = f;
            hVar.d("Animation", InputStream.class, Drawable.class, new com.bumptech.glide.load.resource.drawable.a(new u(arrayListE, false, mVar, 8), 1));
            hVar.d("Animation", ByteBuffer.class, Drawable.class, new com.bumptech.glide.load.resource.drawable.a(new u(arrayListE, false, mVar, 8), 0));
        } else {
            i = i2;
            resources = resources2;
            jVar = f;
        }
        com.bumptech.glide.load.j cVar3 = new com.bumptech.glide.load.resource.drawable.c(applicationContext);
        com.bumptech.glide.load.k c1539b = new C1539b(mVar);
        com.bumptech.glide.load.resource.transcode.b sVar2 = new com.android.billingclient.api.s(10, (byte) 0);
        com.bumptech.glide.load.resource.transcode.b dVar = new com.bumptech.glide.load.resource.transcode.d(1);
        ContentResolver contentResolver = applicationContext.getContentResolver();
        hVar.a(ByteBuffer.class, new C1535c(2));
        hVar.a(InputStream.class, new com.quizlet.data.repository.school.membership.a(mVar, 15));
        hVar.d("Bitmap", ByteBuffer.class, Bitmap.class, c1543f);
        hVar.d("Bitmap", InputStream.class, Bitmap.class, c1538a);
        String str2 = Build.FINGERPRINT;
        if ("robolectric".equals(str2)) {
            str = str2;
            jVar2 = cVar3;
        } else {
            str = str2;
            jVar2 = cVar3;
            hVar.d("Bitmap", ParcelFileDescriptor.class, Bitmap.class, new C1543f(oVar, 1));
        }
        hVar.d("Bitmap", AssetFileDescriptor.class, Bitmap.class, new F(aVar, new com.quizlet.shared.usecase.folderstudymaterials.b(6)));
        com.bumptech.glide.load.j jVar3 = jVar;
        hVar.d("Bitmap", ParcelFileDescriptor.class, Bitmap.class, jVar3);
        com.bumptech.glide.load.model.s sVar3 = A.b;
        hVar.c(Bitmap.class, Bitmap.class, sVar3);
        hVar.d("Bitmap", Bitmap.class, Bitmap.class, new B(0));
        hVar.b(Bitmap.class, c1539b);
        Resources resources3 = resources;
        hVar.d("BitmapDrawable", ByteBuffer.class, BitmapDrawable.class, new C1538a(resources3, c1543f));
        hVar.d("BitmapDrawable", InputStream.class, BitmapDrawable.class, new C1538a(resources3, c1538a));
        hVar.d("BitmapDrawable", ParcelFileDescriptor.class, BitmapDrawable.class, new C1538a(resources3, jVar3));
        hVar.b(BitmapDrawable.class, new com.quizlet.data.repository.searchexplanations.c(6, aVar, c1539b));
        hVar.d("Animation", InputStream.class, com.bumptech.glide.load.resource.gif.b.class, new com.bumptech.glide.load.resource.gif.i(arrayListE, aVar2, mVar));
        hVar.d("Animation", ByteBuffer.class, com.bumptech.glide.load.resource.gif.b.class, aVar2);
        hVar.b(com.bumptech.glide.load.resource.gif.b.class, new retrofit2.adapter.rxjava3.d(6));
        hVar.c(com.bumptech.glide.gifdecoder.d.class, com.bumptech.glide.gifdecoder.d.class, sVar3);
        hVar.d("Bitmap", com.bumptech.glide.gifdecoder.d.class, Bitmap.class, new C1540c(aVar));
        com.bumptech.glide.load.j jVar4 = jVar2;
        hVar.d("legacy_append", Uri.class, Drawable.class, jVar4);
        hVar.d("legacy_append", Uri.class, Bitmap.class, new C1538a(1, jVar4, aVar));
        hVar.h(new com.bumptech.glide.load.data.h(2));
        hVar.c(File.class, ByteBuffer.class, new A(3));
        hVar.c(File.class, InputStream.class, new com.bumptech.glide.load.model.g(new C1535c(5)));
        hVar.d("legacy_append", File.class, File.class, new B(2));
        hVar.c(File.class, ParcelFileDescriptor.class, new com.bumptech.glide.load.model.g(new C1535c(4)));
        hVar.c(File.class, File.class, sVar3);
        hVar.h(new com.bumptech.glide.load.data.m(mVar));
        if (!"robolectric".equals(str)) {
            hVar.h(new com.bumptech.glide.load.data.h(1));
        }
        com.bumptech.glide.load.model.s c1537e = new C1537e(applicationContext, 2);
        com.bumptech.glide.load.model.s c1537e2 = new C1537e(applicationContext, 0);
        com.bumptech.glide.load.model.s c1537e3 = new C1537e(applicationContext, 1);
        Class cls = Integer.TYPE;
        hVar.c(cls, InputStream.class, c1537e);
        hVar.c(Integer.class, InputStream.class, c1537e);
        hVar.c(cls, AssetFileDescriptor.class, c1537e2);
        hVar.c(Integer.class, AssetFileDescriptor.class, c1537e2);
        hVar.c(cls, Drawable.class, c1537e3);
        hVar.c(Integer.class, Drawable.class, c1537e3);
        hVar.c(Uri.class, InputStream.class, new C1537e(applicationContext, 4));
        hVar.c(Uri.class, AssetFileDescriptor.class, new C1537e(applicationContext, 3));
        com.bumptech.glide.load.model.s yVar = new y(resources3, 2);
        com.bumptech.glide.load.model.s yVar2 = new y(resources3, 0);
        com.bumptech.glide.load.model.s yVar3 = new y(resources3, 1);
        hVar.c(Integer.class, Uri.class, yVar);
        hVar.c(cls, Uri.class, yVar);
        hVar.c(Integer.class, AssetFileDescriptor.class, yVar2);
        hVar.c(cls, AssetFileDescriptor.class, yVar2);
        hVar.c(Integer.class, InputStream.class, yVar3);
        hVar.c(cls, InputStream.class, yVar3);
        hVar.c(String.class, InputStream.class, new com.bumptech.glide.integration.okhttp3.b(1));
        hVar.c(Uri.class, InputStream.class, new com.bumptech.glide.integration.okhttp3.b(1));
        hVar.c(String.class, InputStream.class, new A(6));
        hVar.c(String.class, ParcelFileDescriptor.class, new A(5));
        hVar.c(String.class, AssetFileDescriptor.class, new A(4));
        hVar.c(Uri.class, InputStream.class, new C1533a(applicationContext.getAssets(), 1));
        hVar.c(Uri.class, AssetFileDescriptor.class, new C1533a(applicationContext.getAssets(), 0));
        hVar.c(Uri.class, InputStream.class, new b.a(applicationContext));
        hVar.c(Uri.class, InputStream.class, new c.a(applicationContext));
        if (i >= 29) {
            hVar.c(Uri.class, InputStream.class, new com.bumptech.glide.load.model.stream.f(applicationContext));
            hVar.c(Uri.class, ParcelFileDescriptor.class, new com.bumptech.glide.load.model.stream.e(applicationContext));
        }
        hVar.c(Uri.class, InputStream.class, new com.bumptech.glide.load.model.C(contentResolver, 2));
        hVar.c(Uri.class, ParcelFileDescriptor.class, new com.bumptech.glide.load.model.C(contentResolver, 1));
        hVar.c(Uri.class, AssetFileDescriptor.class, new com.bumptech.glide.load.model.C(contentResolver, 0));
        hVar.c(Uri.class, InputStream.class, new A(7));
        hVar.c(URL.class, InputStream.class, new com.bumptech.glide.load.model.stream.j());
        hVar.c(Uri.class, File.class, new m.a(applicationContext));
        hVar.c(com.bumptech.glide.load.model.h.class, InputStream.class, new com.bumptech.glide.integration.okhttp3.b(2));
        hVar.c(byte[].class, ByteBuffer.class, new A(1));
        hVar.c(byte[].class, InputStream.class, new A(2));
        hVar.c(Uri.class, Uri.class, sVar3);
        hVar.c(Drawable.class, Drawable.class, sVar3);
        hVar.d("legacy_append", Drawable.class, Drawable.class, new B(1));
        hVar.i(Bitmap.class, BitmapDrawable.class, new com.bumptech.glide.load.resource.transcode.a(resources3));
        hVar.i(Bitmap.class, byte[].class, sVar2);
        hVar.i(Drawable.class, byte[].class, new com.quizlet.data.repository.classfolder.e(aVar, sVar2, dVar, 5));
        hVar.i(com.bumptech.glide.load.resource.gif.b.class, byte[].class, dVar);
        com.bumptech.glide.load.j f2 = new F(aVar, new com.quizlet.shared.usecase.folderstudymaterials.c(6));
        hVar.d("legacy_append", ByteBuffer.class, Bitmap.class, f2);
        hVar.d("legacy_append", ByteBuffer.class, BitmapDrawable.class, new C1538a(resources3, f2));
        Iterator it2 = list.iterator();
        while (it2.hasNext()) {
            OkHttpGlideModule okHttpGlideModule = (OkHttpGlideModule) it2.next();
            try {
                okHttpGlideModule.getClass();
                hVar.j(new com.bumptech.glide.integration.okhttp3.b(0));
            } catch (AbstractMethodError e) {
                throw new IllegalStateException("Attempting to register a Glide v3 module. If you see this, you or one of your dependencies may be including Glide v3 even though you're using Glide v4. You'll need to find and remove (or update) the offending dependency. The v3 module name is: ".concat(okHttpGlideModule.getClass().getName()), e);
            }
        }
        if (c != null) {
            c.b(applicationContext, glide, hVar);
        }
        return hVar;
    }
}
