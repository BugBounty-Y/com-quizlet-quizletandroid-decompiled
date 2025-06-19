package com.quizlet.data.repository.classmembership;

import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3762x6;
import io.reactivex.rxjava3.functions.h;
import kotlin.collections.K;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final /* synthetic */ class b implements h {
    public final /* synthetic */ int a;
    public final /* synthetic */ c b;
    public final /* synthetic */ long c;

    public /* synthetic */ b(c cVar, long j, int i) {
        this.a = i;
        this.b = cVar;
        this.c = j;
    }

    @Override // io.reactivex.rxjava3.functions.h
    public final Object apply(Object obj) {
        Throwable it2 = (Throwable) obj;
        switch (this.a) {
            case 0:
                Intrinsics.checkNotNullParameter(it2, "it");
                ((org.slf4j.b) this.b.c).j(android.support.v4.media.session.a.g(this.c, ")", new StringBuilder("Error retrieving user class memberships from database for user (")), it2);
                break;
            default:
                Intrinsics.checkNotNullParameter(it2, "it");
                AbstractC3762x6.b((org.slf4j.b) this.b.c, it2, android.support.v4.media.session.a.g(this.c, ")", new StringBuilder("Error retrieving user class memberships from remote for user (")));
                break;
        }
        return K.a;
    }
}
