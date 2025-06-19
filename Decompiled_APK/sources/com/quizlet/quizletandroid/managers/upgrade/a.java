package com.quizlet.quizletandroid.managers.upgrade;

import android.os.Bundle;
import androidx.fragment.app.AbstractC1136h0;
import com.google.android.gms.internal.mlkit_vision_barcode.S;
import com.google.android.gms.internal.mlkit_vision_barcode.T;
import com.quizlet.data.model.C0;
import com.quizlet.data.model.C4135i0;
import com.quizlet.data.model.S0;
import com.quizlet.features.infra.studysetting.data.QuestionSettings;
import com.quizlet.generated.enums.D;
import com.quizlet.generated.enums.E0;
import com.quizlet.generated.enums.EnumC4534z;
import com.quizlet.generated.enums.O1;
import com.quizlet.remote.mapper.base.b;
import com.quizlet.remote.model.explanations.question.RemoteQuestion;
import com.quizlet.remote.model.practicetests.QuestionBanksModel;
import com.quizlet.remote.model.practicetests.QuestionBanksResponse;
import com.quizlet.remote.model.practicetests.RemoteQuestionBanksResponse;
import com.quizlet.remote.model.user.RemoteFullUser;
import com.quizlet.uicommon.ui.common.dialogs.ImageOverlayDialogFragment;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.NoSuchElementException;
import kotlin.collections.B;
import kotlin.collections.C;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.json.internal.s;

/* loaded from: classes3.dex */
public final class a implements com.quizlet.remote.mapper.base.a, com.quizlet.mapper.a, b {
    public final /* synthetic */ int a;

    public /* synthetic */ a(int i) {
        this.a = i;
    }

    public static boolean b(QuestionSettings settings) {
        Intrinsics.checkNotNullParameter(settings, "settings");
        List listJ = B.j(O1.WORD, O1.DEFINITION);
        List list = settings.b;
        if (list != null && list.isEmpty()) {
            return false;
        }
        Iterator it2 = list.iterator();
        while (it2.hasNext()) {
            if (listJ.contains((O1) it2.next())) {
                return true;
            }
        }
        return false;
    }

    public static C4135i0 d(RemoteFullUser remote) {
        String str;
        Intrinsics.checkNotNullParameter(remote, "remote");
        long j = remote.a;
        String str2 = remote.b;
        if (str2 == null) {
            str2 = "";
        }
        Long l = remote.c;
        long jLongValue = l != null ? l.longValue() : 0L;
        Long l2 = remote.d;
        long jLongValue2 = l2 != null ? l2.longValue() : 0L;
        Integer num = remote.e;
        int iIntValue = num != null ? num.intValue() : 0;
        Boolean bool = remote.f;
        boolean zBooleanValue = bool != null ? bool.booleanValue() : false;
        Boolean bool2 = remote.g;
        boolean zBooleanValue2 = bool2 != null ? bool2.booleanValue() : false;
        Boolean bool3 = remote.h;
        boolean zBooleanValue3 = bool3 != null ? bool3.booleanValue() : true;
        String str3 = remote.i;
        if (str3 == null) {
            str3 = "";
        }
        String str4 = remote.j;
        if (str4 == null) {
            str4 = "";
            str = str4;
        } else {
            str = "";
        }
        Long l3 = remote.k;
        long jLongValue3 = l3 != null ? l3.longValue() : 0L;
        Long l4 = remote.l;
        long jLongValue4 = l4 != null ? l4.longValue() : 0L;
        Long l5 = remote.m;
        long jLongValue5 = l5 != null ? l5.longValue() : 0L;
        Boolean bool4 = remote.n;
        boolean zBooleanValue4 = bool4 != null ? bool4.booleanValue() : false;
        Integer num2 = remote.o;
        int iIntValue2 = num2 != null ? num2.intValue() : 0;
        Boolean bool5 = remote.r;
        boolean zBooleanValue5 = bool5 != null ? bool5.booleanValue() : false;
        Boolean bool6 = remote.s;
        boolean zBooleanValue6 = bool6 != null ? bool6.booleanValue() : false;
        Boolean bool7 = remote.t;
        boolean zBooleanValue7 = bool7 != null ? bool7.booleanValue() : false;
        Boolean bool8 = remote.u;
        boolean zBooleanValue8 = bool8 != null ? bool8.booleanValue() : false;
        Boolean bool9 = remote.v;
        boolean zBooleanValue9 = bool9 != null ? bool9.booleanValue() : false;
        Boolean bool10 = remote.w;
        boolean zBooleanValue10 = bool10 != null ? bool10.booleanValue() : false;
        Boolean bool11 = remote.x;
        boolean zBooleanValue11 = bool11 != null ? bool11.booleanValue() : false;
        Boolean bool12 = remote.y;
        boolean zBooleanValue12 = bool12 != null ? bool12.booleanValue() : false;
        Long l6 = remote.B;
        long jLongValue6 = l6 != null ? l6.longValue() : 0L;
        Boolean bool13 = remote.C;
        boolean zBooleanValue13 = bool13 != null ? bool13.booleanValue() : false;
        Boolean bool14 = remote.D;
        boolean zBooleanValue14 = bool14 != null ? bool14.booleanValue() : false;
        Boolean bool15 = remote.E;
        boolean zBooleanValue15 = bool15 != null ? bool15.booleanValue() : false;
        Boolean bool16 = remote.F;
        boolean zBooleanValue16 = bool16 != null ? bool16.booleanValue() : false;
        String str5 = remote.G;
        String str6 = str5 == null ? str : str5;
        String str7 = remote.H;
        return new C4135i0(j, str2, jLongValue, jLongValue2, iIntValue, zBooleanValue, zBooleanValue2, zBooleanValue3, str3, str4, jLongValue3, jLongValue4, jLongValue5, zBooleanValue4, iIntValue2, remote.p, remote.q, zBooleanValue5, zBooleanValue6, zBooleanValue7, zBooleanValue8, zBooleanValue9, zBooleanValue10, zBooleanValue11, zBooleanValue12, remote.z, remote.A, jLongValue6, zBooleanValue13, zBooleanValue14, zBooleanValue15, zBooleanValue16, str6, str7 == null ? str : str7);
    }

    public static C0 f(RemoteQuestion remote) {
        Intrinsics.checkNotNullParameter(remote, "remote");
        long j = remote.a;
        String str = remote.c;
        String str2 = str == null ? "" : str;
        String str3 = remote.d.a;
        String str4 = str3 == null ? "" : str3;
        List list = remote.g;
        ArrayList arrayList = new ArrayList(C.q(list, 10));
        Iterator it2 = list.iterator();
        while (it2.hasNext()) {
            int iIntValue = ((Number) it2.next()).intValue();
            com.quizlet.generated.enums.C c = D.Companion;
            Integer numValueOf = Integer.valueOf(iIntValue);
            c.getClass();
            arrayList.add(com.quizlet.generated.enums.C.a(numValueOf));
        }
        Long l = remote.j;
        return new C0(j, remote.b, str2, remote.e, arrayList, l != null ? l.longValue() : 0L, str4);
    }

    public static void i(String imagePath, AbstractC1136h0 fragmentManager, Integer num) {
        Intrinsics.checkNotNullParameter(imagePath, "imagePath");
        Intrinsics.checkNotNullParameter(fragmentManager, "fragmentManager");
        Intrinsics.checkNotNullParameter(imagePath, "imagePath");
        ImageOverlayDialogFragment imageOverlayDialogFragment = new ImageOverlayDialogFragment();
        Bundle bundle = new Bundle();
        bundle.putString("overlayImagePath", imagePath);
        if (num != null) {
            bundle.putInt("overlayTintColor", num.intValue());
        }
        imageOverlayDialogFragment.setArguments(bundle);
        imageOverlayDialogFragment.O(fragmentManager, ImageOverlayDialogFragment.x);
    }

    @Override // com.quizlet.mapper.a
    public Object a(Object obj) {
        List<QuestionBanksModel> list;
        E0 e0;
        RemoteQuestionBanksResponse input = (RemoteQuestionBanksResponse) obj;
        Intrinsics.checkNotNullParameter(input, "input");
        ArrayList arrayList = new ArrayList();
        QuestionBanksResponse questionBanksResponse = input.d;
        if (questionBanksResponse != null && (list = questionBanksResponse.a) != null) {
            for (QuestionBanksModel questionBanksModel : list) {
                if (questionBanksModel != null) {
                    EnumC4534z.Companion.getClass();
                    String value = questionBanksModel.f;
                    Intrinsics.checkNotNullParameter(value, "value");
                    for (EnumC4534z enumC4534z : EnumC4534z.values()) {
                        if (Intrinsics.b(enumC4534z.a(), value)) {
                            String value2 = questionBanksModel.h;
                            if (value2 != null) {
                                E0.Companion.getClass();
                                Intrinsics.checkNotNullParameter(value2, "value");
                                E0[] e0ArrValues = E0.values();
                                int length = e0ArrValues.length;
                                for (int i = 0; i < length; i++) {
                                    e0 = e0ArrValues[i];
                                    if (!Intrinsics.b(e0.a(), value2)) {
                                    }
                                }
                                throw new NoSuchElementException("Array contains no element matching the predicate.");
                            }
                            e0 = null;
                            arrayList.add(new S0(questionBanksModel.a, questionBanksModel.b, enumC4534z, questionBanksModel.c, questionBanksModel.g, e0));
                        }
                    }
                    throw new NoSuchElementException("Array contains no element matching the predicate.");
                }
            }
        }
        return arrayList;
    }

    @Override // com.quizlet.remote.mapper.base.a
    public /* bridge */ /* synthetic */ Object c(Object obj) {
        switch (this.a) {
            case 2:
                return f((RemoteQuestion) obj);
            default:
                return d((RemoteFullUser) obj);
        }
    }

    @Override // com.quizlet.remote.mapper.base.a
    public List e(List list) {
        switch (this.a) {
            case 2:
                return S.f(this, list);
            default:
                return T.f(this, list);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:24:0x00fe  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public com.quizlet.features.infra.studysetting.data.QuestionSettings g(com.quizlet.features.infra.studysetting.data.QuestionSettings r43, com.quizlet.features.infra.studysetting.data.QuestionSettings r44) {
        /*
            Method dump skipped, instructions count: 614
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.quizletandroid.managers.upgrade.a.g(com.quizlet.features.infra.studysetting.data.QuestionSettings, com.quizlet.features.infra.studysetting.data.QuestionSettings):com.quizlet.features.infra.studysetting.data.QuestionSettings");
    }

    @Override // com.quizlet.remote.mapper.base.c
    public Object h(Object obj) {
        C4135i0 data = (C4135i0) obj;
        Intrinsics.checkNotNullParameter(data, "data");
        return new RemoteFullUser(data.a, data.b, Long.valueOf(data.c), Long.valueOf(data.d), Integer.valueOf(data.e), Boolean.valueOf(data.f), Boolean.valueOf(data.g), Boolean.valueOf(data.h), data.i, data.j, Long.valueOf(data.k), Long.valueOf(data.l), Long.valueOf(data.m), Boolean.valueOf(data.n), Integer.valueOf(data.o), data.p, data.q, Boolean.valueOf(data.r), Boolean.valueOf(data.s), Boolean.valueOf(data.t), Boolean.valueOf(data.u), Boolean.valueOf(data.v), Boolean.valueOf(data.w), Boolean.valueOf(data.x), Boolean.valueOf(data.y), data.z, data.A, Long.valueOf(data.B), Boolean.valueOf(data.C), Boolean.valueOf(data.D), Boolean.valueOf(data.E), Boolean.valueOf(data.F), data.G, data.H);
    }

    public a(s block) {
        this.a = 6;
        Intrinsics.checkNotNullParameter(block, "block");
    }
}
