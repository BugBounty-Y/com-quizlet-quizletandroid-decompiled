package com.quizlet.quizletandroid.ui.profile.data;

import com.google.android.gms.internal.mlkit_vision_barcode.S;
import com.google.android.gms.internal.mlkit_vision_barcode.T;
import com.quizlet.data.model.EnumC4175w;
import com.quizlet.data.model.NotesToValueInfo;
import com.quizlet.data.model.StudySet;
import com.quizlet.data.model.StudySetWithCreator;
import com.quizlet.data.model.TitleInfo;
import com.quizlet.data.model.User;
import com.quizlet.remote.model.notes.RemoteStudyNote;
import com.quizlet.remote.model.set.RemoteSet;
import com.quizlet.remote.model.user.RemoteUser;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import kotlin.collections.C;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class b implements io.reactivex.rxjava3.functions.b, com.quizlet.remote.mapper.base.a, com.quizlet.remote.mapper.base.b, io.reactivex.rxjava3.functions.i {
    public final /* synthetic */ int a;

    public /* synthetic */ b(int i) {
        this.a = i;
    }

    public static StudySet b(RemoteSet remote) {
        Intrinsics.checkNotNullParameter(remote, "remote");
        long j = remote.a;
        Integer num = remote.b;
        int iIntValue = num != null ? num.intValue() : 0;
        Integer num2 = remote.c;
        int iIntValue2 = num2 != null ? num2.intValue() : 0;
        Integer num3 = remote.d;
        int iIntValue3 = num3 != null ? num3.intValue() : 0;
        Long l = remote.e;
        long jLongValue = l != null ? l.longValue() : 0L;
        String str = remote.f;
        if (str == null) {
            str = "";
        }
        String str2 = remote.g;
        if (str2 == null) {
            str2 = "";
        }
        String str3 = remote.h;
        if (str3 == null) {
            str3 = "";
        }
        Boolean bool = remote.i;
        boolean zBooleanValue = bool != null ? bool.booleanValue() : false;
        Boolean bool2 = remote.j;
        boolean zBooleanValue2 = bool2 != null ? bool2.booleanValue() : false;
        Integer num4 = remote.k;
        int iIntValue4 = num4 != null ? num4.intValue() : 0;
        boolean z = zBooleanValue;
        String str4 = remote.m;
        String str5 = str4 == null ? "" : str4;
        Integer num5 = remote.n;
        int iIntValue5 = num5 != null ? num5.intValue() : 0;
        Boolean bool3 = remote.o;
        boolean zBooleanValue3 = bool3 != null ? bool3.booleanValue() : false;
        Integer num6 = remote.p;
        int iIntValue6 = num6 != null ? num6.intValue() : 0;
        Integer num7 = remote.q;
        int iIntValue7 = num7 != null ? num7.intValue() : 0;
        Integer num8 = remote.r;
        int iIntValue8 = num8 != null ? num8.intValue() : 0;
        Boolean bool4 = remote.s;
        boolean zBooleanValue4 = bool4 != null ? bool4.booleanValue() : false;
        String str6 = remote.t;
        String str7 = str6 != null ? str6 : "";
        Integer num9 = remote.w;
        int iIntValue9 = num9 != null ? num9.intValue() : 0;
        Long l2 = remote.x;
        return new StudySet(j, iIntValue, iIntValue2, iIntValue3, jLongValue, str, str2, str3, z, zBooleanValue2, iIntValue4, remote.l, str5, iIntValue5, zBooleanValue3, iIntValue6, iIntValue7, iIntValue8, zBooleanValue4, str7, remote.u, remote.v, iIntValue9, l2 != null ? l2.longValue() : 0L, remote.y, remote.z, remote.A, false, remote.B, 134217728, null);
    }

    public NotesToValueInfo a(RemoteStudyNote remote) {
        Intrinsics.checkNotNullParameter(remote, "remote");
        String str = remote.a;
        if (str == null) {
            throw new IllegalArgumentException("Required value was null.");
        }
        String str2 = remote.b;
        if (str2 == null) {
            throw new IllegalArgumentException("Required value was null.");
        }
        TitleInfo titleInfo = new TitleInfo("", EnumC4175w.COMPLETE, str2);
        RemoteUser remoteUser = remote.c;
        if (remoteUser != null) {
            return new NotesToValueInfo(str, true, titleInfo, null, null, null, null, com.quizlet.quizletandroid.ui.activitycenter.models.a.b(remoteUser), "", null, null, 1656, null);
        }
        throw new IllegalArgumentException("Required value was null.");
    }

    @Override // io.reactivex.rxjava3.functions.b
    public Object apply(Object t1, Object t2) {
        Intrinsics.checkNotNullExpressionValue(t1, "t1");
        Intrinsics.checkNotNullExpressionValue(t2, "t2");
        return CollectionsKt.c0((List) t1, (List) t2);
    }

    @Override // com.quizlet.remote.mapper.base.a
    public /* bridge */ /* synthetic */ Object c(Object obj) {
        switch (this.a) {
            case 2:
                return a((RemoteStudyNote) obj);
            default:
                return b((RemoteSet) obj);
        }
    }

    public ArrayList d(ArrayList users, List sets) {
        Intrinsics.checkNotNullParameter(sets, "sets");
        Intrinsics.checkNotNullParameter(users, "users");
        ArrayList arrayListF = T.f(this, sets);
        LinkedHashMap linkedHashMap = new LinkedHashMap();
        Iterator it2 = users.iterator();
        while (it2.hasNext()) {
            Object next = it2.next();
            Long lValueOf = Long.valueOf(((User) next).a);
            Object arrayList = linkedHashMap.get(lValueOf);
            if (arrayList == null) {
                arrayList = new ArrayList();
                linkedHashMap.put(lValueOf, arrayList);
            }
            ((List) arrayList).add(next);
        }
        ArrayList arrayList2 = new ArrayList(C.q(arrayListF, 10));
        Iterator it3 = arrayListF.iterator();
        while (it3.hasNext()) {
            StudySet studySet = (StudySet) it3.next();
            List list = (List) linkedHashMap.get(Long.valueOf(studySet.e));
            arrayList2.add(new StudySetWithCreator(studySet, list != null ? (User) CollectionsKt.L(list) : null));
        }
        return arrayList2;
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

    @Override // com.quizlet.remote.mapper.base.c
    public Object h(Object obj) {
        StudySet data = (StudySet) obj;
        Intrinsics.checkNotNullParameter(data, "data");
        return new RemoteSet(data.a, Integer.valueOf(data.b), Integer.valueOf(data.c), Integer.valueOf(data.d), Long.valueOf(data.e), data.f, data.g, data.h, Boolean.valueOf(data.i), Boolean.valueOf(data.j), Integer.valueOf(data.k), data.l, data.m, Integer.valueOf(data.n), Boolean.valueOf(data.o), Integer.valueOf(data.p), Integer.valueOf(data.q), Integer.valueOf(data.r), Boolean.valueOf(data.s), data.t, data.u, data.v, Integer.valueOf(data.w), Long.valueOf(data.x), data.y, data.z, data.A, data.C);
    }

    @Override // io.reactivex.rxjava3.functions.i
    public boolean test(Object obj) {
        return true;
    }

    public b(com.quizlet.quizletandroid.ui.activitycenter.models.a userMapper) {
        this.a = 2;
        Intrinsics.checkNotNullParameter(userMapper, "userMapper");
    }
}
