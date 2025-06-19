package com.bumptech.glide.load.model;

import android.content.Context;
import android.content.res.AssetFileDescriptor;
import android.content.res.Resources;
import android.graphics.drawable.Drawable;
import java.io.IOException;
import java.io.InputStream;

/* loaded from: classes.dex */
public final class f implements com.bumptech.glide.load.data.e {
    public final Resources.Theme a;
    public final Resources b;
    public final Object c;
    public final int d;
    public Object e;

    public f(Resources.Theme theme, Resources resources, C1537e c1537e, int i) {
        this.a = theme;
        this.b = resources;
        this.c = c1537e;
        this.d = i;
    }

    @Override // com.bumptech.glide.load.data.e
    public final void cancel() {
    }

    @Override // com.bumptech.glide.load.data.e
    public final void f() throws IOException {
        Object obj = this.e;
        if (obj != null) {
            try {
                switch (((C1537e) this.c).a) {
                    case 0:
                        ((AssetFileDescriptor) obj).close();
                        break;
                    case 1:
                        break;
                    default:
                        ((InputStream) obj).close();
                        break;
                }
            } catch (IOException unused) {
            }
        }
    }

    @Override // com.bumptech.glide.load.data.e
    public final int g() {
        return 1;
    }

    @Override // com.bumptech.glide.load.data.e
    public final Class getDataClass() {
        switch (((C1537e) this.c).a) {
            case 0:
                return AssetFileDescriptor.class;
            case 1:
                return Drawable.class;
            default:
                return InputStream.class;
        }
    }

    @Override // com.bumptech.glide.load.data.e
    public final void h(com.bumptech.glide.g gVar, com.bumptech.glide.load.data.d dVar) throws Resources.NotFoundException {
        Object objOpenRawResourceFd;
        try {
            Object obj = this.c;
            Resources.Theme theme = this.a;
            Resources resources = this.b;
            int i = this.d;
            C1537e c1537e = (C1537e) obj;
            switch (c1537e.a) {
                case 0:
                    objOpenRawResourceFd = resources.openRawResourceFd(i);
                    break;
                case 1:
                    Context context = c1537e.b;
                    objOpenRawResourceFd = com.google.android.gms.internal.mlkit_vision_common.B.d(context, context, i, theme);
                    break;
                default:
                    objOpenRawResourceFd = resources.openRawResource(i);
                    break;
            }
            this.e = objOpenRawResourceFd;
            dVar.i(objOpenRawResourceFd);
        } catch (Resources.NotFoundException e) {
            dVar.a(e);
        }
    }
}
