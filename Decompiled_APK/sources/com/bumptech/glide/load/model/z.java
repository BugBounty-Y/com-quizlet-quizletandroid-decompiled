package com.bumptech.glide.load.model;

import android.net.Uri;
import android.text.TextUtils;
import java.io.File;
import java.net.URL;

/* loaded from: classes.dex */
public final class z implements r {
    public final /* synthetic */ int a;
    public final r b;

    public /* synthetic */ z(r rVar, int i) {
        this.a = i;
        this.b = rVar;
    }

    @Override // com.bumptech.glide.load.model.r
    public final /* bridge */ /* synthetic */ boolean a(Object obj) {
        switch (this.a) {
            case 0:
                break;
            default:
                break;
        }
        return true;
    }

    @Override // com.bumptech.glide.load.model.r
    public final q b(Object obj, int i, int i2, com.bumptech.glide.load.h hVar) {
        Uri uriFromFile;
        switch (this.a) {
            case 0:
                String str = (String) obj;
                if (TextUtils.isEmpty(str)) {
                    uriFromFile = null;
                } else if (str.charAt(0) == '/') {
                    uriFromFile = Uri.fromFile(new File(str));
                } else {
                    Uri uri = Uri.parse(str);
                    uriFromFile = uri.getScheme() == null ? Uri.fromFile(new File(str)) : uri;
                }
                if (uriFromFile == null) {
                    return null;
                }
                r rVar = this.b;
                if (rVar.a(uriFromFile)) {
                    return rVar.b(uriFromFile, i, i2, hVar);
                }
                return null;
            default:
                return this.b.b(new h((URL) obj), i, i2, hVar);
        }
    }
}
