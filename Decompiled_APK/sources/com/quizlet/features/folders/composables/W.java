package com.quizlet.features.folders.composables;

import com.quizlet.features.folders.data.C4272b;
import com.quizlet.quizletandroid.ui.library.data.C4648b;
import com.quizlet.quizletandroid.ui.library.data.C4649c;
import com.quizlet.search.data.term.TermSearchUiModel;
import java.io.IOException;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.internal.C5057k;

/* loaded from: classes3.dex */
public final class W implements Function0 {
    public final /* synthetic */ int a;
    public final Object b;
    public final /* synthetic */ Object c;

    public /* synthetic */ W(int i, Object obj, Object obj2) {
        this.a = i;
        this.b = obj;
        this.c = obj2;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() throws Throwable {
        okhttp3.internal.http2.a aVar;
        Throwable th;
        switch (this.a) {
            case 0:
                ((Function1) this.b).invoke(new C4272b((com.quizlet.ui.models.content.listitem.k) this.c));
                return Unit.a;
            case 1:
                ((Function1) this.b).invoke(new C4272b((com.quizlet.ui.models.content.listitem.l) this.c));
                return Unit.a;
            case 2:
                ((Function1) this.b).invoke(new C4272b((com.quizlet.ui.models.content.listitem.m) this.c));
                return Unit.a;
            case 3:
                ((Function1) this.b).invoke(new C4272b((com.quizlet.ui.models.content.listitem.n) this.c));
                return Unit.a;
            case 4:
                ((Function1) this.b).invoke(new C4272b((com.quizlet.ui.models.content.listitem.i) this.c));
                return Unit.a;
            case 5:
                ((Function1) this.b).invoke(new C4272b((com.quizlet.ui.models.content.listitem.h) this.c));
                return Unit.a;
            case 6:
                ((Function2) this.b).invoke(30, ((com.quizlet.features.practicetest.results.data.x) this.c).a);
                return Unit.a;
            case 7:
                ((Function1) this.b).invoke(Long.valueOf(((C4648b) this.c).b.a));
                return Unit.a;
            case 8:
                ((Function1) this.b).invoke(Long.valueOf(((C4649c) this.c).b.a));
                return Unit.a;
            case 9:
                ((Function1) this.b).invoke(Long.valueOf(((com.quizlet.quizletandroid.ui.library.data.L) ((com.quizlet.quizletandroid.ui.library.data.K) this.c)).a.a));
                return Unit.a;
            case 10:
                ((Function1) this.b).invoke((com.quizlet.ui.models.content.carditem.f) this.c);
                return Unit.a;
            case 11:
                ((Function1) this.b).invoke((com.quizlet.ui.models.content.carditem.g) this.c);
                return Unit.a;
            case 12:
                ((Function1) this.b).invoke((com.quizlet.ui.models.content.carditem.e) this.c);
                return Unit.a;
            case 13:
                ((Function1) this.b).invoke((com.quizlet.ui.models.content.carditem.h) this.c);
                return Unit.a;
            case 14:
                ((Function1) this.b).invoke((com.quizlet.ui.models.content.carditem.a) this.c);
                return Unit.a;
            case 15:
                ((Function1) this.b).invoke((TermSearchUiModel) this.c);
                return Unit.a;
            case 16:
                return new C5057k((KSerializer) ((Function1) ((com.quizlet.remote.model.report.c) this.b).a).invoke((kotlin.reflect.c) this.c));
            default:
                okhttp3.internal.http2.n nVar = (okhttp3.internal.http2.n) this.c;
                okhttp3.internal.http2.r rVar = (okhttp3.internal.http2.r) this.b;
                okhttp3.internal.http2.a aVar2 = okhttp3.internal.http2.a.INTERNAL_ERROR;
                IOException e = null;
                try {
                    try {
                        Intrinsics.checkNotNullParameter(this, "handler");
                    } catch (Throwable th2) {
                        th = th2;
                    }
                } catch (IOException e2) {
                    e = e2;
                    aVar = aVar2;
                }
                if (!rVar.a(true, this)) {
                    throw new IOException("Required SETTINGS preface not received");
                }
                do {
                    try {
                    } catch (Throwable th3) {
                        th = th3;
                        aVar = aVar2;
                        nVar.a(aVar, aVar2, e);
                        okhttp3.internal.b.d(rVar);
                        throw th;
                    }
                } while (rVar.a(false, this));
                aVar = okhttp3.internal.http2.a.NO_ERROR;
                try {
                    try {
                        nVar.a(aVar, okhttp3.internal.http2.a.CANCEL, null);
                    } catch (IOException e3) {
                        e = e3;
                        okhttp3.internal.http2.a aVar3 = okhttp3.internal.http2.a.PROTOCOL_ERROR;
                        nVar.a(aVar3, aVar3, e);
                        okhttp3.internal.b.d(rVar);
                        return Unit.a;
                    }
                    okhttp3.internal.b.d(rVar);
                    return Unit.a;
                } catch (Throwable th4) {
                    th = th4;
                    nVar.a(aVar, aVar2, e);
                    okhttp3.internal.b.d(rVar);
                    throw th;
                }
        }
    }

    public W(okhttp3.internal.http2.n nVar, okhttp3.internal.http2.r reader) {
        this.a = 17;
        Intrinsics.checkNotNullParameter(reader, "reader");
        this.c = nVar;
        this.b = reader;
    }
}
