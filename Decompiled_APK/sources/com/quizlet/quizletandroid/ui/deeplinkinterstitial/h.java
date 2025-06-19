package com.quizlet.quizletandroid.ui.deeplinkinterstitial;

import android.net.Uri;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class h extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public Uri j;
    public int k;
    public final /* synthetic */ i l;
    public final /* synthetic */ Uri m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public h(i iVar, Uri uri, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = iVar;
        this.m = uri;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new h(this.l, this.m, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((h) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:233:0x04ac, code lost:
    
        if (r2.equalsIgnoreCase("study-guides") == true) goto L240;
     */
    /* JADX WARN: Code restructure failed: missing block: B:267:0x054b, code lost:
    
        if (r4.equalsIgnoreCase("test-questions") == true) goto L274;
     */
    /* JADX WARN: Code restructure failed: missing block: B:343:0x074f, code lost:
    
        if (r1 != r3) goto L345;
     */
    /* JADX WARN: Removed duplicated region for block: B:136:0x025b  */
    /* JADX WARN: Removed duplicated region for block: B:137:0x0262  */
    /* JADX WARN: Removed duplicated region for block: B:162:0x02fe  */
    /* JADX WARN: Removed duplicated region for block: B:163:0x031a  */
    /* JADX WARN: Removed duplicated region for block: B:165:0x031d  */
    /* JADX WARN: Removed duplicated region for block: B:166:0x0324  */
    /* JADX WARN: Removed duplicated region for block: B:21:0x0084  */
    /* JADX WARN: Removed duplicated region for block: B:68:0x014e  */
    /* JADX WARN: Removed duplicated region for block: B:78:0x017a  */
    /* JADX WARN: Removed duplicated region for block: B:79:0x0181  */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r20) {
        /*
            Method dump skipped, instructions count: 1877
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.quizletandroid.ui.deeplinkinterstitial.h.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
