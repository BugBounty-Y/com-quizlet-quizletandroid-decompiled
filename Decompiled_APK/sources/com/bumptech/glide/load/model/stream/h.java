package com.bumptech.glide.load.model.stream;

import android.content.Context;
import android.database.Cursor;
import android.net.Uri;
import android.os.Environment;
import android.provider.MediaStore;
import android.text.TextUtils;
import com.bumptech.glide.load.model.q;
import com.bumptech.glide.load.model.r;
import com.google.android.gms.internal.mlkit_vision_common.A;
import java.io.File;
import java.io.FileNotFoundException;

/* loaded from: classes.dex */
public final class h implements com.bumptech.glide.load.data.e {
    public static final String[] k = {"_data"};
    public final Context a;
    public final r b;
    public final r c;
    public final Uri d;
    public final int e;
    public final int f;
    public final com.bumptech.glide.load.h g;
    public final Class h;
    public volatile boolean i;
    public volatile com.bumptech.glide.load.data.e j;

    public h(Context context, r rVar, r rVar2, Uri uri, int i, int i2, com.bumptech.glide.load.h hVar, Class cls) {
        this.a = context.getApplicationContext();
        this.b = rVar;
        this.c = rVar2;
        this.d = uri;
        this.e = i;
        this.f = i2;
        this.g = hVar;
        this.h = cls;
    }

    public final com.bumptech.glide.load.data.e a() throws Throwable {
        q qVarB;
        boolean zIsExternalStorageLegacy = Environment.isExternalStorageLegacy();
        Cursor cursor = null;
        Context context = this.a;
        com.bumptech.glide.load.h hVar = this.g;
        int i = this.f;
        int i2 = this.e;
        if (zIsExternalStorageLegacy) {
            Uri uri = this.d;
            try {
                Cursor cursorQuery = context.getContentResolver().query(uri, k, null, null, null);
                if (cursorQuery != null) {
                    try {
                        if (cursorQuery.moveToFirst()) {
                            String string = cursorQuery.getString(cursorQuery.getColumnIndexOrThrow("_data"));
                            if (TextUtils.isEmpty(string)) {
                                throw new FileNotFoundException("File path was empty in media store for: " + uri);
                            }
                            File file = new File(string);
                            cursorQuery.close();
                            qVarB = this.b.b(file, i2, i, hVar);
                        }
                    } catch (Throwable th) {
                        th = th;
                        cursor = cursorQuery;
                        if (cursor != null) {
                            cursor.close();
                        }
                        throw th;
                    }
                }
                throw new FileNotFoundException("Failed to media store entry for: " + uri);
            } catch (Throwable th2) {
                th = th2;
            }
        } else {
            Uri requireOriginal = this.d;
            boolean zE = A.e(requireOriginal);
            r rVar = this.c;
            if (zE && requireOriginal.getPathSegments().contains("picker")) {
                qVarB = rVar.b(requireOriginal, i2, i, hVar);
            } else {
                if (context.checkSelfPermission("android.permission.ACCESS_MEDIA_LOCATION") == 0) {
                    requireOriginal = MediaStore.setRequireOriginal(requireOriginal);
                }
                qVarB = rVar.b(requireOriginal, i2, i, hVar);
            }
        }
        if (qVarB != null) {
            return qVarB.c;
        }
        return null;
    }

    @Override // com.bumptech.glide.load.data.e
    public final void cancel() {
        this.i = true;
        com.bumptech.glide.load.data.e eVar = this.j;
        if (eVar != null) {
            eVar.cancel();
        }
    }

    @Override // com.bumptech.glide.load.data.e
    public final void f() {
        com.bumptech.glide.load.data.e eVar = this.j;
        if (eVar != null) {
            eVar.f();
        }
    }

    @Override // com.bumptech.glide.load.data.e
    public final int g() {
        return 1;
    }

    @Override // com.bumptech.glide.load.data.e
    public final Class getDataClass() {
        return this.h;
    }

    @Override // com.bumptech.glide.load.data.e
    public final void h(com.bumptech.glide.g gVar, com.bumptech.glide.load.data.d dVar) throws Throwable {
        try {
            com.bumptech.glide.load.data.e eVarA = a();
            if (eVarA == null) {
                dVar.a(new IllegalArgumentException("Failed to build fetcher for: " + this.d));
            } else {
                this.j = eVarA;
                if (this.i) {
                    cancel();
                } else {
                    eVarA.h(gVar, dVar);
                }
            }
        } catch (FileNotFoundException e) {
            dVar.a(e);
        }
    }
}
