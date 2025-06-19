package com.quizlet.quizletandroid;

/* renamed from: com.quizlet.quizletandroid.r, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4633r {
    public final /* synthetic */ int a;
    public final /* synthetic */ t b;

    public /* synthetic */ C4633r(t tVar, int i) {
        this.a = i;
        this.b = tVar;
    }

    /* JADX WARN: Type inference failed for: r3v0, types: [java.lang.Object, java.util.Map] */
    /* JADX WARN: Type inference failed for: r3v1, types: [java.lang.Object, java.util.Map] */
    /* JADX WARN: Type inference failed for: r3v2, types: [java.lang.Object, java.util.Map] */
    public final com.quizlet.remote.model.notes.e a(String str, Enum r6) {
        switch (this.a) {
            case 0:
                u uVar = this.b.a;
                com.quizlet.infra.contracts.growthbook.a aVar = (com.quizlet.infra.contracts.growthbook.a) uVar.y0.get();
                com.google.mlkit.common.sdkinternal.b bVar = uVar.m;
                return new com.quizlet.remote.model.notes.e(aVar, new com.quizlet.featuregate.contracts.growthbook.a(com.quizlet.featuregate.growthbook.b.a), str, (com.quizlet.featuregate.contracts.enums.c) r6);
            case 1:
                u uVar2 = this.b.a;
                com.quizlet.infra.contracts.growthbook.a aVar2 = (com.quizlet.infra.contracts.growthbook.a) uVar2.y0.get();
                com.google.mlkit.common.sdkinternal.b bVar2 = uVar2.m;
                return new com.quizlet.remote.model.notes.e(aVar2, new com.quizlet.featuregate.contracts.growthbook.a(com.quizlet.featuregate.growthbook.b.a), str, (com.quizlet.featuregate.contracts.enums.b) r6);
            default:
                u uVar3 = this.b.a;
                com.quizlet.infra.contracts.growthbook.a aVar3 = (com.quizlet.infra.contracts.growthbook.a) uVar3.y0.get();
                com.google.mlkit.common.sdkinternal.b bVar3 = uVar3.m;
                return new com.quizlet.remote.model.notes.e(aVar3, new com.quizlet.featuregate.contracts.growthbook.a(com.quizlet.featuregate.growthbook.b.a), str, (com.quizlet.featuregate.contracts.enums.a) r6);
        }
    }
}
