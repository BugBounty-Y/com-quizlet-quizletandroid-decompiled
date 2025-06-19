package com.quizlet.remote.model.universaluploadflow;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.data.exceptions.universaluploadflow.UniversalUploadFlowException;
import com.quizlet.generated.enums.EnumC4529w0;
import com.quizlet.remote.model.base.ApiThreeWrapper;
import com.quizlet.remote.service.D;
import java.util.UUID;
import kotlin.Unit;
import kotlin.collections.CollectionsKt;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.H;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C;
import kotlinx.coroutines.E;

/* loaded from: classes3.dex */
public final class f extends i implements Function2 {
    public int j;
    public final /* synthetic */ int k;
    public final /* synthetic */ com.quizlet.remote.model.notes.e l;
    public final /* synthetic */ String m;
    public final /* synthetic */ H n;
    public final /* synthetic */ int o;
    public final /* synthetic */ int p;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public f(int i, com.quizlet.remote.model.notes.e eVar, String str, H h, int i2, int i3, h hVar) {
        super(2, hVar);
        this.k = i;
        this.l = eVar;
        this.m = str;
        this.n = h;
        this.o = i2;
        this.p = i3;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        return new f(this.k, this.l, this.m, this.n, this.o, this.p, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((f) create((C) obj, (h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:44:0x00b0 -> B:16:0x0030). Please report as a decompilation issue!!! */
    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) throws UniversalUploadFlowException {
        UniversalUploadFlowPracticeTestsStatusResponse universalUploadFlowPracticeTestsStatusResponse;
        UniversalUploadFlowPracticeTestsStatusModels universalUploadFlowPracticeTestsStatusModels;
        UniversalUploadFlowPracticeTestsStatus universalUploadFlowPracticeTestsStatus;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            long j = this.k;
            this.j = 1;
            if (E.n(j, this) != aVar) {
            }
            return aVar;
        }
        if (i != 1) {
            if (i == 2) {
                try {
                    Z.e(obj);
                } catch (Exception unused) {
                    H h = this.n;
                    int i2 = h.a + 1;
                    h.a = i2;
                    if (i2 > this.o) {
                        throw new UniversalUploadFlowException("Max server error retries reached");
                    }
                }
                universalUploadFlowPracticeTestsStatusResponse = (UniversalUploadFlowPracticeTestsStatusResponse) ((ApiThreeWrapper) obj).a();
                if (universalUploadFlowPracticeTestsStatusResponse != null || (universalUploadFlowPracticeTestsStatusModels = universalUploadFlowPracticeTestsStatusResponse.d) == null || (universalUploadFlowPracticeTestsStatus = (UniversalUploadFlowPracticeTestsStatus) CollectionsKt.firstOrNull(universalUploadFlowPracticeTestsStatusModels.a)) == null) {
                    throw new UniversalUploadFlowException("Failed to retrieve status");
                }
                int iA = EnumC4529w0.COMPLETE.a();
                int i3 = universalUploadFlowPracticeTestsStatus.b;
                if (i3 == iA) {
                    return Unit.a;
                }
                if (i3 == EnumC4529w0.ERROR.a() || i3 == EnumC4529w0.INELIGIBLE.a() || i3 == EnumC4529w0.MODERATION.a()) {
                    throw new UniversalUploadFlowException(universalUploadFlowPracticeTestsStatus.c);
                }
                long j2 = this.p;
                this.j = 3;
                if (E.n(j2, this) != aVar) {
                }
                return aVar;
            }
            if (i != 3) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
        }
        Z.e(obj);
        D d = (D) this.l.b;
        String str = this.m;
        String string = UUID.randomUUID().toString();
        Intrinsics.checkNotNullExpressionValue(string, "toString(...)");
        this.j = 2;
        obj = d.c(str, string, this);
        if (obj == aVar) {
            return aVar;
        }
        universalUploadFlowPracticeTestsStatusResponse = (UniversalUploadFlowPracticeTestsStatusResponse) ((ApiThreeWrapper) obj).a();
        if (universalUploadFlowPracticeTestsStatusResponse != null) {
        }
        throw new UniversalUploadFlowException("Failed to retrieve status");
    }
}
