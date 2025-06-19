package com.iab.omid.library.pubmatic.internal;

import android.content.Context;
import android.os.Handler;
import com.iab.omid.library.pubmatic.internal.d;
import com.iab.omid.library.pubmatic.walking.TreeWalker;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.Iterator;

/* loaded from: classes2.dex */
public class i implements d.a, com.iab.omid.library.pubmatic.devicevolume.c {
    private static i f;
    private float a = DefinitionKt.NO_Float_VALUE;
    private final com.iab.omid.library.pubmatic.devicevolume.e b;
    private final com.iab.omid.library.pubmatic.devicevolume.b c;
    private com.iab.omid.library.pubmatic.devicevolume.d d;
    private c e;

    public i(com.iab.omid.library.pubmatic.devicevolume.e eVar, com.iab.omid.library.pubmatic.devicevolume.b bVar) {
        this.b = eVar;
        this.c = bVar;
    }

    private c a() {
        if (this.e == null) {
            this.e = c.c();
        }
        return this.e;
    }

    public static i c() {
        if (f == null) {
            f = new i(new com.iab.omid.library.pubmatic.devicevolume.e(), new com.iab.omid.library.pubmatic.devicevolume.b());
        }
        return f;
    }

    public float b() {
        return this.a;
    }

    public void d() {
        b.g().a(this);
        b.g().e();
        TreeWalker.getInstance().h();
        this.d.c();
    }

    public void e() {
        TreeWalker.getInstance().j();
        b.g().f();
        this.d.d();
    }

    @Override // com.iab.omid.library.pubmatic.devicevolume.c
    public void a(float f2) {
        this.a = f2;
        Iterator<com.iab.omid.library.pubmatic.adsession.a> it2 = a().a().iterator();
        while (it2.hasNext()) {
            it2.next().getAdSessionStatePublisher().a(f2);
        }
    }

    public void a(Context context) {
        this.d = this.b.a(new Handler(), context, this.c.a(), this);
    }

    @Override // com.iab.omid.library.pubmatic.internal.d.a
    public void a(boolean z) {
        if (z) {
            TreeWalker.getInstance().h();
        } else {
            TreeWalker.getInstance().g();
        }
    }
}
