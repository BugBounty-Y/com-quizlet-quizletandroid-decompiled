package com.airbnb.lottie;

import android.graphics.Bitmap;
import android.graphics.Rect;
import androidx.collection.C0219q;
import androidx.collection.W;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;

/* loaded from: classes.dex */
public final class h {
    public HashMap c;
    public HashMap d;
    public float e;
    public HashMap f;
    public ArrayList g;
    public W h;
    public C0219q i;
    public ArrayList j;
    public Rect k;
    public float l;
    public float m;
    public float n;
    public boolean o;
    public final B a = new B();
    public final HashSet b = new HashSet();
    public int p = 0;

    public final void a(String str) {
        com.airbnb.lottie.utils.c.b(str);
        this.b.add(str);
    }

    public final float b() {
        return (long) (((this.m - this.l) / this.n) * 1000.0f);
    }

    public final Map c() {
        float fC = com.airbnb.lottie.utils.i.c();
        if (fC != this.e) {
            for (Map.Entry entry : this.d.entrySet()) {
                HashMap map = this.d;
                String str = (String) entry.getKey();
                w wVar = (w) entry.getValue();
                float f = this.e / fC;
                int i = (int) (wVar.a * f);
                int i2 = (int) (wVar.b * f);
                w wVar2 = new w(wVar.c, i, wVar.d, wVar.e, i2);
                Bitmap bitmap = wVar.f;
                if (bitmap != null) {
                    wVar2.f = Bitmap.createScaledBitmap(bitmap, i, i2, true);
                }
                map.put(str, wVar2);
            }
        }
        this.e = fC;
        return this.d;
    }

    public final com.airbnb.lottie.model.h d(String str) {
        int size = this.g.size();
        for (int i = 0; i < size; i++) {
            com.airbnb.lottie.model.h hVar = (com.airbnb.lottie.model.h) this.g.get(i);
            String str2 = hVar.a;
            if (str2.equalsIgnoreCase(str) || (str2.endsWith("\r") && str2.substring(0, str2.length() - 1).equalsIgnoreCase(str))) {
                return hVar;
            }
        }
        return null;
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("LottieComposition:\n");
        Iterator it2 = this.j.iterator();
        while (it2.hasNext()) {
            sb.append(((com.airbnb.lottie.model.layer.e) it2.next()).a("\t"));
        }
        return sb.toString();
    }
}
