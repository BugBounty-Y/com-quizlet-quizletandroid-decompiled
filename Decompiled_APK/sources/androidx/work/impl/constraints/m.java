package androidx.work.impl.constraints;

import android.content.Context;
import android.net.ConnectivityManager;
import android.os.Build;
import com.facebook.s;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Locale;
import kotlin.collections.C4933y;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class m implements s {
    public final ArrayList a;

    /*  JADX ERROR: JadxRuntimeException in pass: RegionMakerVisitor
        jadx.core.utils.exceptions.JadxRuntimeException: Failed to find switch 'out' block (already processed)
        	at jadx.core.dex.visitors.regions.maker.SwitchRegionMaker.calcSwitchOut(SwitchRegionMaker.java:200)
        	at jadx.core.dex.visitors.regions.maker.SwitchRegionMaker.process(SwitchRegionMaker.java:61)
        	at jadx.core.dex.visitors.regions.maker.RegionMaker.traverse(RegionMaker.java:112)
        	at jadx.core.dex.visitors.regions.maker.RegionMaker.makeRegion(RegionMaker.java:66)
        	at jadx.core.dex.visitors.regions.maker.IfRegionMaker.process(IfRegionMaker.java:101)
        	at jadx.core.dex.visitors.regions.maker.RegionMaker.traverse(RegionMaker.java:106)
        	at jadx.core.dex.visitors.regions.maker.RegionMaker.makeRegion(RegionMaker.java:66)
        	at jadx.core.dex.visitors.regions.maker.IfRegionMaker.process(IfRegionMaker.java:101)
        	at jadx.core.dex.visitors.regions.maker.RegionMaker.traverse(RegionMaker.java:106)
        	at jadx.core.dex.visitors.regions.maker.RegionMaker.makeRegion(RegionMaker.java:66)
        	at jadx.core.dex.visitors.regions.maker.LoopRegionMaker.process(LoopRegionMaker.java:124)
        	at jadx.core.dex.visitors.regions.maker.RegionMaker.traverse(RegionMaker.java:89)
        	at jadx.core.dex.visitors.regions.maker.RegionMaker.makeRegion(RegionMaker.java:66)
        	at jadx.core.dex.visitors.regions.maker.RegionMaker.makeMthRegion(RegionMaker.java:48)
        	at jadx.core.dex.visitors.regions.RegionMakerVisitor.visit(RegionMakerVisitor.java:25)
        */
    /* JADX WARN: Removed duplicated region for block: B:28:0x005f  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public m(com.perimeterx.mobile_sdk.doctor_app.model.d r9, com.perimeterx.mobile_sdk.doctor_app.f r10) {
        /*
            r8 = this;
            java.lang.String r0 = "summary"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r9, r0)
            java.lang.String r0 = "productType"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r10, r0)
            r8.<init>()
            java.util.ArrayList r1 = new java.util.ArrayList
            r1.<init>()
            r8.a = r1
            com.perimeterx.mobile_sdk.doctor_app.model.g[] r1 = com.perimeterx.mobile_sdk.doctor_app.model.g.values()
            int r2 = r1.length
            r3 = 0
        L1a:
            if (r3 >= r2) goto L6c
            r4 = r1[r3]
            r4.getClass()
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r10, r0)
            int r5 = r4.ordinal()
            r6 = 15
            if (r5 == r6) goto L5f
            if (r5 == 0) goto L5f
            r6 = 1
            if (r5 == r6) goto L5f
            r7 = 2
            if (r5 == r7) goto L5f
            r7 = 3
            if (r5 == r7) goto L5f
            r7 = 4
            if (r5 == r7) goto L5f
            int r5 = r10.ordinal()
            if (r5 == 0) goto L54
            if (r5 != r6) goto L4e
            int r5 = r4.ordinal()
            r6 = 19
            if (r5 == r6) goto L5f
            switch(r5) {
                case 11: goto L5f;
                case 12: goto L5f;
                case 13: goto L5f;
                case 14: goto L5f;
                default: goto L4d;
            }
        L4d:
            goto L69
        L4e:
            kotlin.NoWhenBranchMatchedException r9 = new kotlin.NoWhenBranchMatchedException
            r9.<init>()
            throw r9
        L54:
            int r5 = r4.ordinal()
            switch(r5) {
                case 5: goto L5f;
                case 6: goto L5f;
                case 7: goto L5f;
                case 8: goto L5f;
                case 9: goto L5f;
                case 10: goto L5f;
                default: goto L5b;
            }
        L5b:
            switch(r5) {
                case 16: goto L5f;
                case 17: goto L5f;
                case 18: goto L5f;
                default: goto L5e;
            }
        L5e:
            goto L69
        L5f:
            java.util.ArrayList r5 = r8.a
            com.perimeterx.mobile_sdk.doctor_app.model.f r6 = new com.perimeterx.mobile_sdk.doctor_app.model.f
            r6.<init>(r4, r9)
            r5.add(r6)
        L69:
            int r3 = r3 + 1
            goto L1a
        L6c:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.work.impl.constraints.m.<init>(com.perimeterx.mobile_sdk.doctor_app.model.d, com.perimeterx.mobile_sdk.doctor_app.f):void");
    }

    @Override // com.facebook.s
    public void a(String key, String value) {
        Intrinsics.checkNotNullParameter(key, "key");
        Intrinsics.checkNotNullParameter(value, "value");
        String str = String.format(Locale.US, "%s=%s", Arrays.copyOf(new Object[]{key, URLEncoder.encode(value, "UTF-8")}, 2));
        Intrinsics.checkNotNullExpressionValue(str, "format(locale, format, *args)");
        this.a.add(str);
    }

    public m(androidx.work.impl.constraints.trackers.j trackers) {
        h hVar;
        Intrinsics.checkNotNullParameter(trackers, "trackers");
        androidx.work.impl.constraints.controllers.d dVar = new androidx.work.impl.constraints.controllers.d(trackers.b);
        androidx.work.impl.constraints.controllers.d dVar2 = new androidx.work.impl.constraints.controllers.d(trackers.c, (byte) 0);
        androidx.work.impl.constraints.controllers.d dVar3 = new androidx.work.impl.constraints.controllers.d(trackers.e, (char) 0);
        androidx.work.impl.constraints.trackers.g gVar = trackers.d;
        androidx.work.impl.constraints.controllers.d dVar4 = new androidx.work.impl.constraints.controllers.d(gVar, 2);
        androidx.work.impl.constraints.controllers.d dVar5 = new androidx.work.impl.constraints.controllers.d(gVar, 3);
        androidx.work.impl.constraints.controllers.g gVar2 = new androidx.work.impl.constraints.controllers.g(gVar);
        androidx.work.impl.constraints.controllers.f fVar = new androidx.work.impl.constraints.controllers.f(gVar);
        if (Build.VERSION.SDK_INT >= 28) {
            int i = o.a;
            Context context = trackers.a;
            Intrinsics.checkNotNullParameter(context, "context");
            Object systemService = context.getSystemService("connectivity");
            Intrinsics.e(systemService, "null cannot be cast to non-null type android.net.ConnectivityManager");
            hVar = new h((ConnectivityManager) systemService);
        } else {
            hVar = null;
        }
        androidx.work.impl.constraints.controllers.e[] elements = {dVar, dVar2, dVar3, dVar4, dVar5, gVar2, fVar, hVar};
        Intrinsics.checkNotNullParameter(elements, "elements");
        ArrayList controllers = C4933y.z(elements);
        Intrinsics.checkNotNullParameter(controllers, "controllers");
        this.a = controllers;
    }

    public m(ArrayList arrayList) {
        this.a = arrayList;
    }
}
