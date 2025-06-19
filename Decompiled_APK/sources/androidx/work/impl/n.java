package androidx.work.impl;

import android.text.TextUtils;
import androidx.lifecycle.C1247h;
import androidx.work.EnumC1441o;
import androidx.work.Q;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3402v2;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3406w2;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class n extends AbstractC3406w2 {
    public static final String i = androidx.work.z.e("WorkContinuationImpl");
    public final r a;
    public final String b;
    public final EnumC1441o c;
    public final List d;
    public final ArrayList e;
    public final ArrayList f = new ArrayList();
    public boolean g;
    public androidx.work.G h;

    public n(r rVar, String str, EnumC1441o enumC1441o, List list) {
        this.a = rVar;
        this.b = str;
        this.c = enumC1441o;
        this.d = list;
        this.e = new ArrayList(list.size());
        for (int i2 = 0; i2 < list.size(); i2++) {
            if (enumC1441o == EnumC1441o.a && ((Q) list.get(i2)).b.u != Long.MAX_VALUE) {
                throw new IllegalArgumentException("Next Schedule Time Override must be used with ExistingPeriodicWorkPolicyUPDATE (preferably) or KEEP");
            }
            String string = ((Q) list.get(i2)).a.toString();
            Intrinsics.checkNotNullExpressionValue(string, "id.toString()");
            this.e.add(string);
            this.f.add(string);
        }
    }

    public static HashSet d(n nVar) {
        HashSet hashSet = new HashSet();
        nVar.getClass();
        return hashSet;
    }

    public final androidx.work.G c() {
        if (this.g) {
            androidx.work.z.c().f(i, "Already enqueued work ids (" + TextUtils.join(", ", this.e) + ")");
        } else {
            r rVar = this.a;
            this.h = AbstractC3402v2.c(rVar.b.m, "EnqueueRunnable_" + this.c.name(), rVar.d.a, new C1247h(this, 5));
        }
        return this.h;
    }
}
