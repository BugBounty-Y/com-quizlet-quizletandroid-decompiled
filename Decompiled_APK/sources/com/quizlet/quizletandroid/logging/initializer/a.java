package com.quizlet.quizletandroid.logging.initializer;

import com.google.android.gms.internal.mlkit_vision_barcode.S;
import com.quizlet.data.model.R0;
import com.quizlet.data.model.X;
import com.quizlet.data.model.l2;
import com.quizlet.quizletandroid.ui.joincontenttofolder.j;
import com.quizlet.quizletandroid.ui.profile.data.b;
import com.quizlet.remote.model.classset.RemoteClassSet;
import com.quizlet.remote.model.metering.RemoteMeteringInfo;
import com.quizlet.remote.model.practicetests.PracticeTestsImageDataResponse;
import com.quizlet.remote.model.session.RemoteSession;
import com.quizlet.remote.model.set.RemoteSet;
import com.quizlet.remote.model.universaluploadflow.UniversalUploadFlowFlashcardSetsResponse;
import com.quizlet.remote.model.user.RemoteUser;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import kotlin.collections.C;
import kotlin.collections.K;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a implements com.quizlet.remote.mapper.base.a, com.quizlet.mapper.a {
    public final /* synthetic */ int a;

    public /* synthetic */ a(int i) {
        this.a = i;
    }

    public static X b(RemoteMeteringInfo remote) {
        Intrinsics.checkNotNullParameter(remote, "remote");
        return new X(remote.a, remote.b);
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r4v4, types: [kotlin.collections.K] */
    /* JADX WARN: Type inference failed for: r4v5, types: [java.util.List] */
    /* JADX WARN: Type inference failed for: r4v6, types: [java.util.ArrayList] */
    @Override // com.quizlet.mapper.a
    public Object a(Object obj) {
        ?? arrayList;
        switch (this.a) {
            case 3:
                PracticeTestsImageDataResponse input = (PracticeTestsImageDataResponse) obj;
                Intrinsics.checkNotNullParameter(input, "input");
                return new R0(input.a, input.b);
            default:
                UniversalUploadFlowFlashcardSetsResponse input2 = (UniversalUploadFlowFlashcardSetsResponse) obj;
                Intrinsics.checkNotNullParameter(input2, "input");
                List list = input2.b;
                ArrayList arrayList2 = new ArrayList(C.q(list, 10));
                Iterator it2 = list.iterator();
                while (it2.hasNext()) {
                    arrayList2.add(b.b((RemoteSet) it2.next()));
                }
                List list2 = input2.a;
                ArrayList arrayList3 = new ArrayList(C.q(list2, 10));
                Iterator it3 = list2.iterator();
                while (it3.hasNext()) {
                    arrayList3.add(j.i((RemoteClassSet) it3.next()));
                }
                List list3 = input2.c;
                ArrayList arrayList4 = new ArrayList(C.q(list3, 10));
                Iterator it4 = list3.iterator();
                while (it4.hasNext()) {
                    arrayList4.add(com.quizlet.quizletandroid.ui.onboarding.a.b((RemoteSession) it4.next()));
                }
                List list4 = input2.d;
                if (list4 != null) {
                    arrayList = new ArrayList(C.q(list4, 10));
                    Iterator it5 = list4.iterator();
                    while (it5.hasNext()) {
                        arrayList.add(com.quizlet.quizletandroid.ui.activitycenter.models.a.b((RemoteUser) it5.next()));
                    }
                } else {
                    arrayList = K.a;
                }
                return new l2(arrayList3, arrayList2, arrayList4, arrayList);
        }
    }

    @Override // com.quizlet.remote.mapper.base.a
    public /* bridge */ /* synthetic */ Object c(Object obj) {
        return b((RemoteMeteringInfo) obj);
    }

    @Override // com.quizlet.remote.mapper.base.a
    public List e(List list) {
        return S.f(this, list);
    }

    public a(j classSetMapper, b setMapper, com.quizlet.quizletandroid.ui.onboarding.a sessionMapper, com.quizlet.quizletandroid.ui.activitycenter.models.a userMapper) {
        this.a = 4;
        Intrinsics.checkNotNullParameter(classSetMapper, "classSetMapper");
        Intrinsics.checkNotNullParameter(setMapper, "setMapper");
        Intrinsics.checkNotNullParameter(sessionMapper, "sessionMapper");
        Intrinsics.checkNotNullParameter(userMapper, "userMapper");
    }
}
