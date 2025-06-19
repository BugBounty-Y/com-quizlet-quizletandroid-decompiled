package com.quizlet.quizletandroid.ui.folder.logging;

import android.util.Log;
import com.google.android.gms.internal.mlkit_vision_barcode.S;
import com.google.android.gms.internal.mlkit_vision_barcode.T;
import com.quizlet.data.model.A1;
import com.quizlet.data.model.AbstractC4119d0;
import com.quizlet.data.model.BasicCourseFolder;
import com.quizlet.data.model.ContentFolder;
import com.quizlet.data.model.Course;
import com.quizlet.data.model.D;
import com.quizlet.data.model.FullCourseFolder;
import com.quizlet.data.model.J;
import com.quizlet.data.model.P;
import com.quizlet.data.model.School;
import com.quizlet.generated.enums.M0;
import com.quizlet.remote.mapper.base.b;
import com.quizlet.remote.model.base.PagingInfo;
import com.quizlet.remote.model.classfolder.RemoteClassFolder;
import com.quizlet.remote.model.course.RemoteCourse;
import com.quizlet.remote.model.folder.RemoteFolder;
import com.quizlet.remote.model.school.RemoteSchool;
import com.snowplowanalytics.snowplow.tracker.c;
import java.util.List;
import kotlin.NoWhenBranchMatchedException;
import kotlin.jvm.internal.Intrinsics;
import okio.C5091h;
import okio.internal.e;
import okio.k;
import okio.x;

/* loaded from: classes3.dex */
public final class a implements b, com.quizlet.remote.mapper.base.a, c {
    public final /* synthetic */ int a;

    public /* synthetic */ a(int i) {
        this.a = i;
    }

    public static x f(String str, boolean z) {
        Intrinsics.checkNotNullParameter(str, "<this>");
        k kVar = e.a;
        Intrinsics.checkNotNullParameter(str, "<this>");
        C5091h c5091h = new C5091h();
        c5091h.u0(str);
        return e.d(c5091h, z);
    }

    public static A1 i(PagingInfo data) {
        Intrinsics.checkNotNullParameter(data, "data");
        return new A1(data.a, data.b, data.c);
    }

    public static RemoteFolder j(AbstractC4119d0 data) {
        Intrinsics.checkNotNullParameter(data, "data");
        if (data instanceof ContentFolder) {
            ContentFolder contentFolder = (ContentFolder) data;
            long j = contentFolder.l;
            return new RemoteFolder(j >= 0 ? Long.valueOf(j) : null, Long.valueOf(contentFolder.o), Long.valueOf(contentFolder.q), contentFolder.r, contentFolder.s, Long.valueOf(contentFolder.t), Boolean.valueOf(contentFolder.u), contentFolder.v, contentFolder.m, contentFolder.w, Long.valueOf(contentFolder.n), contentFolder.p, null, null, null, null, null, null, null, null, 1044480, null);
        }
        if (!(data instanceof J)) {
            if (!(data instanceof P)) {
                throw new NoWhenBranchMatchedException();
            }
            P p = (P) data;
            long j2 = p.a;
            return new RemoteFolder(j2 >= 0 ? Long.valueOf(j2) : null, Long.valueOf(p.d), null, null, null, null, null, null, p.b, null, Long.valueOf(p.c), p.e, null, null, null, null, null, null, null, null, 1044480, null);
        }
        J j3 = (J) data;
        long jA = j3.a();
        return new RemoteFolder(jA >= 0 ? Long.valueOf(jA) : null, Long.valueOf(j3.c()), Long.valueOf(j3.h()), j3.g(), null, Long.valueOf(j3.i()), Boolean.valueOf(j3.k()), j3.j(), j3.d(), j3.f(), Long.valueOf(j3.b()), j3.e(), null, null, Boolean.TRUE, null, null, null, null, null, 1028096, null);
    }

    @Override // com.snowplowanalytics.snowplow.tracker.c
    public void a(String tag, String msg) {
        Intrinsics.checkNotNullParameter(tag, "tag");
        Intrinsics.checkNotNullParameter(msg, "msg");
    }

    @Override // com.snowplowanalytics.snowplow.tracker.c
    public void b(String tag, String msg) {
        Intrinsics.checkNotNullParameter(tag, "tag");
        Intrinsics.checkNotNullParameter(msg, "msg");
        Log.e(tag, msg);
    }

    @Override // com.quizlet.remote.mapper.base.a
    public Object c(Object obj) {
        switch (this.a) {
            case 1:
                RemoteClassFolder remote = (RemoteClassFolder) obj;
                Intrinsics.checkNotNullParameter(remote, "remote");
                Long l = remote.a;
                Boolean bool = remote.d;
                boolean zBooleanValue = bool != null ? bool.booleanValue() : false;
                Long l2 = remote.e;
                long jLongValue = l2 != null ? l2.longValue() : 0L;
                Long l3 = remote.f;
                long jLongValue2 = l3 != null ? l3.longValue() : 0L;
                Boolean bool2 = remote.i;
                return new D(l, remote.c, remote.b, zBooleanValue, jLongValue, remote.h, remote.g, jLongValue2, bool2 != null ? bool2.booleanValue() : false);
            case 2:
                return g((RemoteFolder) obj);
            default:
                return i((PagingInfo) obj);
        }
    }

    @Override // com.snowplowanalytics.snowplow.tracker.c
    public void d(String tag, String msg) {
        Intrinsics.checkNotNullParameter(tag, "tag");
        Intrinsics.checkNotNullParameter(msg, "msg");
    }

    @Override // com.quizlet.remote.mapper.base.a
    public List e(List list) {
        switch (this.a) {
            case 1:
                return T.f(this, list);
            case 2:
                return T.f(this, list);
            default:
                return S.f(this, list);
        }
    }

    public AbstractC4119d0 g(RemoteFolder remote) {
        Intrinsics.checkNotNullParameter(remote, "remote");
        boolean z = remote.i;
        Long l = remote.b;
        Long l2 = remote.k;
        Long l3 = remote.a;
        if (z) {
            Intrinsics.d(l3);
            return new P(true, l3.longValue(), l2 != null ? l2.longValue() : 0L, remote.l, l != null ? l.longValue() : 0L);
        }
        boolean zB = Intrinsics.b(remote.o, Boolean.TRUE);
        Boolean bool = remote.g;
        Long l4 = remote.f;
        String str = remote.d;
        Long l5 = remote.c;
        if (!zB) {
            Intrinsics.d(l3);
            long jLongValue = l3.longValue();
            long jLongValue2 = l != null ? l.longValue() : 0L;
            long jLongValue3 = l5 != null ? l5.longValue() : 0L;
            String str2 = str == null ? "" : str;
            String str3 = remote.e;
            String str4 = str3 == null ? "" : str3;
            long jLongValue4 = l4 != null ? l4.longValue() : 0L;
            boolean zBooleanValue = bool != null ? bool.booleanValue() : false;
            long jLongValue5 = l2 != null ? l2.longValue() : 0L;
            Long l6 = remote.m;
            int iLongValue = l6 != null ? (int) l6.longValue() : 0;
            Integer num = remote.n;
            return new ContentFolder(jLongValue, false, jLongValue5, jLongValue2, remote.l, jLongValue3, str2, str4, jLongValue4, zBooleanValue, remote.h, remote.j, Integer.valueOf(iLongValue), Integer.valueOf(num != null ? num.intValue() : 0), null, 16384, null);
        }
        M0 m0 = null;
        RemoteSchool remoteSchool = remote.t;
        School schoolA = remoteSchool != null ? com.quizlet.remote.model.school.a.a(remoteSchool) : null;
        RemoteCourse remoteCourse = remote.s;
        Course courseA = remoteCourse != null ? com.quizlet.remote.model.course.c.a(remoteCourse) : null;
        Integer num2 = remote.r;
        if (schoolA != null && courseA != null) {
            Intrinsics.d(l3);
            long jLongValue6 = l3.longValue();
            long jLongValue7 = l2 != null ? l2.longValue() : 0L;
            long jLongValue8 = l5 != null ? l5.longValue() : 0L;
            String str5 = str == null ? "" : str;
            long jLongValue9 = l4 != null ? l4.longValue() : 0L;
            boolean zBooleanValue2 = bool != null ? bool.booleanValue() : false;
            M0.Companion.getClass();
            M0[] m0ArrValues = M0.values();
            int length = m0ArrValues.length;
            while (true) {
                if (i >= length) {
                    break;
                }
                M0 m02 = m0ArrValues[i];
                int iA = m02.a();
                if (num2 != null && iA == num2.intValue()) {
                    m0 = m02;
                    break;
                }
                i++;
            }
            if (m0 == null) {
                m0 = M0.NONE;
            }
            return new FullCourseFolder(jLongValue6, false, jLongValue7, 0L, remote.l, jLongValue8, jLongValue9, str5, zBooleanValue2, remote.h, remote.j, courseA, schoolA, null, m0, 8192, null);
        }
        Intrinsics.d(l3);
        long jLongValue10 = l3.longValue();
        long jLongValue11 = l2 != null ? l2.longValue() : 0L;
        long jLongValue12 = l != null ? l.longValue() : 0L;
        long jLongValue13 = l5 != null ? l5.longValue() : 0L;
        String str6 = str == null ? "" : str;
        long jLongValue14 = l4 != null ? l4.longValue() : 0L;
        boolean zBooleanValue3 = bool != null ? bool.booleanValue() : false;
        String str7 = remote.p + ", " + remote.q;
        M0.Companion.getClass();
        M0[] m0ArrValues2 = M0.values();
        int length2 = m0ArrValues2.length;
        while (true) {
            if (i >= length2) {
                break;
            }
            M0 m03 = m0ArrValues2[i];
            int iA2 = m03.a();
            if (num2 != null && iA2 == num2.intValue()) {
                m0 = m03;
                break;
            }
            i++;
        }
        if (m0 == null) {
            m0 = M0.NONE;
        }
        return new BasicCourseFolder(jLongValue10, false, jLongValue11, jLongValue12, remote.l, jLongValue13, jLongValue14, str6, zBooleanValue3, remote.h, remote.j, str7, null, m0, 4096, null);
    }

    @Override // com.quizlet.remote.mapper.base.c
    public Object h(Object obj) {
        switch (this.a) {
            case 1:
                D data = (D) obj;
                Intrinsics.checkNotNullParameter(data, "data");
                Long l = data.a;
                Boolean boolValueOf = Boolean.valueOf(data.d);
                Long lValueOf = Long.valueOf(data.e);
                Long lValueOf2 = Long.valueOf(data.h);
                Boolean boolValueOf2 = Boolean.valueOf(data.i);
                return new RemoteClassFolder(l, data.c, data.b, boolValueOf, lValueOf, lValueOf2, data.g, data.f, boolValueOf2);
            default:
                return j((AbstractC4119d0) obj);
        }
    }

    public a(com.quizlet.remote.model.school.a schoolMapper, com.quizlet.remote.model.course.c courseMapper) {
        this.a = 2;
        Intrinsics.checkNotNullParameter(schoolMapper, "schoolMapper");
        Intrinsics.checkNotNullParameter(courseMapper, "courseMapper");
    }
}
