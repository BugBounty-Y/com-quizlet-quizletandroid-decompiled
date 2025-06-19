package com.quizlet.quizletandroid.ui.onboarding;

import com.google.android.gms.internal.mlkit_vision_barcode.S;
import com.google.android.gms.internal.mlkit_vision_barcode.T;
import com.quizlet.data.model.B;
import com.quizlet.data.model.H1;
import com.quizlet.generated.enums.A1;
import com.quizlet.generated.enums.F1;
import com.quizlet.generated.enums.G1;
import com.quizlet.generated.enums.z1;
import com.quizlet.remote.model.login.EmailCheckResponse;
import com.quizlet.remote.model.login.EmailData;
import com.quizlet.remote.model.login.ResponseData;
import com.quizlet.remote.model.login.ValidateEmail;
import com.quizlet.remote.model.session.RemoteSession;
import java.util.List;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a implements com.quizlet.remote.mapper.base.b, com.quizlet.remote.mapper.base.a {
    public final /* synthetic */ int a;

    public /* synthetic */ a(int i) {
        this.a = i;
    }

    public static B a(EmailCheckResponse remote) {
        EmailData emailData;
        Intrinsics.checkNotNullParameter(remote, "remote");
        ResponseData responseData = (ResponseData) CollectionsKt.O(0, remote.d);
        ValidateEmail validateEmail = (responseData == null || (emailData = responseData.a) == null) ? null : emailData.a;
        return new B(validateEmail != null ? validateEmail.b : false, (validateEmail != null ? validateEmail.e : null) != null);
    }

    public static H1 b(RemoteSession remote) {
        Intrinsics.checkNotNullParameter(remote, "remote");
        long j = remote.a;
        G1.Companion.getClass();
        G1 g1A = F1.a(remote.d);
        A1.Companion.getClass();
        A1 a1A = z1.a(remote.g);
        Long l = remote.f;
        long jLongValue = l != null ? l.longValue() : -1L;
        Long l2 = remote.h;
        long jLongValue2 = l2 != null ? l2.longValue() : 0L;
        Boolean bool = remote.j;
        boolean zBooleanValue = bool != null ? bool.booleanValue() : false;
        Boolean bool2 = remote.i;
        boolean zBooleanValue2 = bool2 != null ? bool2.booleanValue() : false;
        Long l3 = remote.k;
        return new H1(j, remote.b, remote.c, g1A, a1A, remote.e, jLongValue, jLongValue2, zBooleanValue, zBooleanValue2, l3 != null ? l3.longValue() : 0L);
    }

    @Override // com.quizlet.remote.mapper.base.a
    public /* bridge */ /* synthetic */ Object c(Object obj) {
        switch (this.a) {
            case 2:
                return a((EmailCheckResponse) obj);
            default:
                return b((RemoteSession) obj);
        }
    }

    @Override // com.quizlet.remote.mapper.base.a
    public List e(List list) {
        switch (this.a) {
            case 2:
                return T.f(this, list);
            default:
                return S.f(this, list);
        }
    }

    @Override // com.quizlet.remote.mapper.base.c
    public Object h(Object obj) {
        B data = (B) obj;
        Intrinsics.checkNotNullParameter(data, "data");
        throw new IllegalStateException("Should not map local models to remote if they are not persistent");
    }

    public a(com.quizlet.remote.model.school.a schoolMapper, com.quizlet.remote.model.course.c courseMapper) {
        this.a = 1;
        Intrinsics.checkNotNullParameter(schoolMapper, "schoolMapper");
        Intrinsics.checkNotNullParameter(courseMapper, "courseMapper");
    }
}
