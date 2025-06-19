package com.quizlet.quizletandroid.ui.profile;

import android.text.Spannable;
import android.text.TextUtils;
import com.google.android.gms.internal.mlkit_vision_barcode.T;
import com.quizlet.data.model.C4179x0;
import com.quizlet.data.model.InterfaceC4176w0;
import com.quizlet.data.model.SimpleImage;
import com.quizlet.data.model.U1;
import com.quizlet.data.model.X1;
import com.quizlet.data.model.o2;
import com.quizlet.generated.enums.P;
import com.quizlet.generated.enums.Q;
import com.quizlet.generated.enums.S;
import com.quizlet.remote.model.explanations.RemoteSimpleImage;
import com.quizlet.remote.model.metering.RemoteMeteringInfo;
import com.quizlet.remote.model.set.RemoteSetClassification;
import com.quizlet.remote.model.set.RemoteSetLineage;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import kotlin.collections.C;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.D;

/* loaded from: classes3.dex */
public final class p implements com.quizlet.remote.mapper.base.a, com.quizlet.remote.mapper.base.b, com.snowplowanalytics.snowplow.tracker.c, io.reactivex.rxjava3.functions.h {
    public final /* synthetic */ int a;

    public /* synthetic */ p(int i) {
        this.a = i;
    }

    public static InterfaceC4176w0 g(RemoteMeteringInfo remoteMeteringInfo, Integer num, P eventType, Long l, long j) {
        S sA;
        Intrinsics.checkNotNullParameter(eventType, "eventType");
        if (num != null) {
            Q q = S.Companion;
            int iIntValue = num.intValue();
            q.getClass();
            sA = Q.a(iIntValue);
        } else {
            sA = S.UNKNOWN;
        }
        S s = sA;
        return remoteMeteringInfo == null ? new o2(eventType, l, j, s) : new C4179x0(remoteMeteringInfo.a, remoteMeteringInfo.b, eventType, l, j, s);
    }

    public static SimpleImage i(RemoteSimpleImage remote) {
        Intrinsics.checkNotNullParameter(remote, "remote");
        return new SimpleImage(remote.a, remote.b, remote.c);
    }

    public static U1 j(RemoteSetClassification remote) {
        Intrinsics.checkNotNullParameter(remote, "remote");
        long j = remote.a;
        List<RemoteSetLineage> list = remote.c;
        ArrayList arrayList = new ArrayList(C.q(list, 10));
        for (RemoteSetLineage remoteSetLineage : list) {
            arrayList.add(new X1(remoteSetLineage.a, remoteSetLineage.b));
        }
        return new U1(j, remote.b, arrayList);
    }

    @Override // com.snowplowanalytics.snowplow.tracker.c
    public void a(String tag, String msg) {
        Intrinsics.checkNotNullParameter(tag, "tag");
        Intrinsics.checkNotNullParameter(msg, "msg");
        timber.log.c.a.a(android.support.v4.media.session.a.l(tag, ": ", msg), new Object[0]);
    }

    @Override // io.reactivex.rxjava3.functions.h
    public Object apply(Object obj) {
        return obj;
    }

    @Override // com.snowplowanalytics.snowplow.tracker.c
    public void b(String tag, String msg) {
        Intrinsics.checkNotNullParameter(tag, "tag");
        Intrinsics.checkNotNullParameter(msg, "msg");
        timber.log.c.a.o(android.support.v4.media.session.a.l(tag, ": ", msg), new Object[0]);
    }

    @Override // com.quizlet.remote.mapper.base.a
    public /* bridge */ /* synthetic */ Object c(Object obj) {
        switch (this.a) {
            case 1:
                return i((RemoteSimpleImage) obj);
            default:
                return j((RemoteSetClassification) obj);
        }
    }

    @Override // com.snowplowanalytics.snowplow.tracker.c
    public void d(String tag, String msg) {
        Intrinsics.checkNotNullParameter(tag, "tag");
        Intrinsics.checkNotNullParameter(msg, "msg");
        timber.log.c.a.m(android.support.v4.media.session.a.l(tag, ": ", msg), new Object[0]);
    }

    @Override // com.quizlet.remote.mapper.base.a
    public List e(List list) {
        switch (this.a) {
            case 1:
                return com.google.android.gms.internal.mlkit_vision_barcode.S.f(this, list);
            default:
                return T.f(this, list);
        }
    }

    public String f(Spannable text) {
        Intrinsics.checkNotNullParameter(text, "text");
        Object[] spans = text.getSpans(0, text.length(), Object.class);
        List listAsList = Arrays.asList(Arrays.copyOf(spans, spans.length));
        StringBuilder sb = new StringBuilder("\n");
        char c = '\n';
        sb.append(D.p(D.p(text.toString(), '\n', (char) 182), (char) 8203, (char) 172));
        sb.append("  length = " + text.length());
        for (Object obj : listAsList) {
            int spanStart = text.getSpanStart(obj);
            int spanEnd = text.getSpanEnd(obj);
            int length = text.length() + 5;
            sb.append(c);
            if (spanStart > 0) {
                String strJoin = TextUtils.join("", Collections.nCopies(spanStart, " "));
                Intrinsics.checkNotNullExpressionValue(strJoin, "join(...)");
                sb.append(strJoin);
                length -= spanStart;
            }
            int spanFlags = text.getSpanFlags(obj);
            int i = spanFlags & 51;
            int i2 = (spanFlags & 48) >>> 4;
            int i3 = spanFlags & 3;
            int i4 = spanEnd - spanStart;
            if (i4 > 0) {
                if (i2 == 1) {
                    sb.append('>');
                } else if (i2 == 2) {
                    sb.append('<');
                } else if (i2 == 3) {
                    sb.append(spanStart == 0 ? '<' : '>');
                }
                length--;
            } else if (i == 17) {
                sb.append('>');
            } else if (i == 18) {
                sb.append('x');
            } else if (i == 33) {
                sb.append('!');
            } else if (i == 34) {
                sb.append('<');
            } else if (i == 51) {
                if (spanStart == 0) {
                    sb.append('!');
                } else if (spanStart == text.length()) {
                    sb.append('<');
                } else {
                    sb.append('>');
                }
            }
            int i5 = i4 - 1;
            if (i5 > 0) {
                String strJoin2 = TextUtils.join("", Collections.nCopies(i5, "-"));
                Intrinsics.checkNotNullExpressionValue(strJoin2, "join(...)");
                sb.append(strJoin2);
                length -= i5;
            }
            if (i4 > 0) {
                if (i3 == 1) {
                    sb.append('>');
                } else if (i3 == 2) {
                    sb.append('<');
                } else if (i3 == 3) {
                    sb.append(spanEnd != text.length() ? '>' : '<');
                }
                length--;
            }
            String strJoin3 = TextUtils.join("", Collections.nCopies(length, " "));
            Intrinsics.checkNotNullExpressionValue(strJoin3, "join(...)");
            sb.append(strJoin3);
            sb.append("   ");
            String str = String.format("%03d", Arrays.copyOf(new Object[]{Integer.valueOf(spanStart)}, 1));
            Intrinsics.checkNotNullExpressionValue(str, "format(...)");
            sb.append(str);
            sb.append(" -> ");
            String str2 = String.format("%03d", Arrays.copyOf(new Object[]{Integer.valueOf(spanEnd)}, 1));
            Intrinsics.checkNotNullExpressionValue(str2, "format(...)");
            sb.append(str2);
            sb.append(" : ");
            sb.append(obj.getClass().getSimpleName());
            c = '\n';
        }
        String string = sb.toString();
        Intrinsics.checkNotNullExpressionValue(string, "toString(...)");
        return string;
    }

    @Override // com.quizlet.remote.mapper.base.c
    public Object h(Object obj) {
        U1 data = (U1) obj;
        Intrinsics.checkNotNullParameter(data, "data");
        long j = data.a;
        ArrayList arrayList = data.c;
        ArrayList arrayList2 = new ArrayList(C.q(arrayList, 10));
        Iterator it2 = arrayList.iterator();
        while (it2.hasNext()) {
            X1 x1 = (X1) it2.next();
            arrayList2.add(new RemoteSetLineage(x1.a, x1.b));
        }
        return new RemoteSetClassification(j, data.b, arrayList2);
    }

    public String toString() {
        switch (this.a) {
            case 5:
                return "IdentityFunction";
            default:
                return super.toString();
        }
    }
}
