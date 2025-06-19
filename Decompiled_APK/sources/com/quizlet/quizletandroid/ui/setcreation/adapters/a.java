package com.quizlet.quizletandroid.ui.setcreation.adapters;

import com.google.android.gms.internal.mlkit_vision_barcode.T;
import com.quizlet.data.model.K0;
import com.quizlet.data.model.W;
import com.quizlet.data.model.i2;
import com.quizlet.generated.enums.A0;
import com.quizlet.generated.enums.C0;
import com.quizlet.generated.enums.C4504n0;
import com.quizlet.generated.enums.C4531x0;
import com.quizlet.generated.enums.C4535z0;
import com.quizlet.generated.enums.EnumC4507o0;
import com.quizlet.generated.enums.EnumC4533y0;
import com.quizlet.remote.model.explanations.feedback.RemoteExplanationsFeedback;
import com.quizlet.remote.model.practicetests.PracticeTestConfigurationResponse;
import com.quizlet.remote.model.term.RemoteTerm;
import java.util.ArrayList;
import java.util.List;
import java.util.NoSuchElementException;
import kotlin.collections.C;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a implements com.quizlet.remote.mapper.base.c, com.quizlet.mapper.a, com.quizlet.remote.mapper.base.b {
    public final /* synthetic */ int a;

    public /* synthetic */ a(int i) {
        this.a = i;
    }

    public static i2 b(RemoteTerm remote) {
        Intrinsics.checkNotNullParameter(remote, "remote");
        long j = remote.a;
        Long l = remote.g;
        return new i2(j, l != null ? l.longValue() : 0L, remote.b, remote.c, remote.d, remote.e, remote.f, remote.h, remote.i, remote.j, remote.k);
    }

    public static RemoteExplanationsFeedback d(W data) {
        Intrinsics.checkNotNullParameter(data, "data");
        return new RemoteExplanationsFeedback(data.a, "width: " + data.b + ", height: " + data.c, data.d);
    }

    @Override // com.quizlet.mapper.a
    public Object a(Object obj) {
        PracticeTestConfigurationResponse input = (PracticeTestConfigurationResponse) obj;
        Intrinsics.checkNotNullParameter(input, "input");
        int i = input.a;
        List<String> list = input.b;
        ArrayList arrayList = new ArrayList(C.q(list, 10));
        for (String str : list) {
            EnumC4533y0.Companion.getClass();
            arrayList.add(C4531x0.a(str));
        }
        C0.Companion.getClass();
        String value = input.d;
        Intrinsics.checkNotNullParameter(value, "value");
        C0[] c0ArrValues = C0.values();
        int length = c0ArrValues.length;
        int i2 = 0;
        while (i2 < length) {
            int i3 = i2;
            C0 c0 = c0ArrValues[i3];
            if (Intrinsics.b(c0.a(), value)) {
                List<String> list2 = input.g;
                ArrayList arrayList2 = new ArrayList(C.q(list2, 10));
                for (String str2 : list2) {
                    A0.Companion.getClass();
                    arrayList2.add(C4535z0.a(str2));
                }
                List<String> list3 = input.h;
                ArrayList arrayList3 = new ArrayList(C.q(list3, 10));
                for (String str3 : list3) {
                    EnumC4507o0.Companion.getClass();
                    arrayList3.add(C4504n0.a(str3));
                }
                return new K0(i, arrayList, arrayList2, arrayList3, c0, input.e, input.f, input.c);
            }
            i2 = i3 + 1;
        }
        throw new NoSuchElementException("Array contains no element matching the predicate.");
    }

    @Override // com.quizlet.remote.mapper.base.a
    public /* bridge */ /* synthetic */ Object c(Object obj) {
        return b((RemoteTerm) obj);
    }

    @Override // com.quizlet.remote.mapper.base.a
    public List e(List list) {
        return T.f(this, list);
    }

    @Override // com.quizlet.remote.mapper.base.c
    public Object h(Object obj) {
        switch (this.a) {
            case 1:
                return d((W) obj);
            default:
                i2 data = (i2) obj;
                Intrinsics.checkNotNullParameter(data, "data");
                return new RemoteTerm(data.a, data.c, data.d, data.e, data.f, data.g, Long.valueOf(data.b), data.h, data.i, data.j, data.k);
        }
    }
}
