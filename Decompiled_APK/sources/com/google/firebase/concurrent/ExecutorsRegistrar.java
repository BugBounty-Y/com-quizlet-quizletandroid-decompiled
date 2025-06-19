package com.google.firebase.concurrent;

import android.annotation.SuppressLint;
import com.google.android.gms.internal.ads.C2537qm;
import com.google.android.gms.internal.mlkit_vision_common.y4;
import com.google.firebase.components.ComponentRegistrar;
import com.google.firebase.components.l;
import com.google.firebase.components.n;
import com.google.firebase.components.q;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.ScheduledExecutorService;

@SuppressLint({"ThreadPoolCreation"})
/* loaded from: classes2.dex */
public class ExecutorsRegistrar implements ComponentRegistrar {
    public static final l a = new l(new com.google.firebase.components.f(2));
    public static final l b = new l(new com.google.firebase.components.f(3));
    public static final l c = new l(new com.google.firebase.components.f(4));
    public static final l d = new l(new com.google.firebase.components.f(5));

    @Override // com.google.firebase.components.ComponentRegistrar
    public final List getComponents() {
        q qVar = new q(com.google.firebase.annotations.concurrent.a.class, ScheduledExecutorService.class);
        q[] qVarArr = {new q(com.google.firebase.annotations.concurrent.a.class, ExecutorService.class), new q(com.google.firebase.annotations.concurrent.a.class, Executor.class)};
        HashSet hashSet = new HashSet();
        HashSet hashSet2 = new HashSet();
        HashSet hashSet3 = new HashSet();
        hashSet.add(qVar);
        for (q qVar2 : qVarArr) {
            y4.b(qVar2, "Null interface");
        }
        Collections.addAll(hashSet, qVarArr);
        com.google.firebase.components.a aVar = new com.google.firebase.components.a(null, new HashSet(hashSet), new HashSet(hashSet2), 0, 0, new n(1), hashSet3);
        q qVar3 = new q(com.google.firebase.annotations.concurrent.b.class, ScheduledExecutorService.class);
        q[] qVarArr2 = {new q(com.google.firebase.annotations.concurrent.b.class, ExecutorService.class), new q(com.google.firebase.annotations.concurrent.b.class, Executor.class)};
        HashSet hashSet4 = new HashSet();
        HashSet hashSet5 = new HashSet();
        HashSet hashSet6 = new HashSet();
        hashSet4.add(qVar3);
        for (q qVar4 : qVarArr2) {
            y4.b(qVar4, "Null interface");
        }
        Collections.addAll(hashSet4, qVarArr2);
        com.google.firebase.components.a aVar2 = new com.google.firebase.components.a(null, new HashSet(hashSet4), new HashSet(hashSet5), 0, 0, new n(2), hashSet6);
        q qVar5 = new q(com.google.firebase.annotations.concurrent.c.class, ScheduledExecutorService.class);
        q[] qVarArr3 = {new q(com.google.firebase.annotations.concurrent.c.class, ExecutorService.class), new q(com.google.firebase.annotations.concurrent.c.class, Executor.class)};
        HashSet hashSet7 = new HashSet();
        HashSet hashSet8 = new HashSet();
        HashSet hashSet9 = new HashSet();
        hashSet7.add(qVar5);
        for (q qVar6 : qVarArr3) {
            y4.b(qVar6, "Null interface");
        }
        Collections.addAll(hashSet7, qVarArr3);
        com.google.firebase.components.a aVar3 = new com.google.firebase.components.a(null, new HashSet(hashSet7), new HashSet(hashSet8), 0, 0, new n(3), hashSet9);
        C2537qm c2537qmA = com.google.firebase.components.a.a(new q(com.google.firebase.annotations.concurrent.d.class, Executor.class));
        c2537qmA.f = new n(4);
        return Arrays.asList(aVar, aVar2, aVar3, c2537qmA.b());
    }
}
