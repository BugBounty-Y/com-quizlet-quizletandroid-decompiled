package com.quizlet.quizletandroid.ui.common.images.capture;

import android.content.Context;
import android.graphics.Point;
import android.graphics.Rect;
import android.os.Build;
import android.view.WindowManager;
import androidx.work.impl.t;
import com.facebook.appevents.g;
import com.google.android.gms.internal.mlkit_vision_barcode.S;
import com.google.android.gms.internal.mlkit_vision_barcode.T;
import com.quizlet.data.model.Exercise;
import com.quizlet.qutils.android.e;
import com.quizlet.remote.model.explanations.toc.RemoteExercise;
import com.quizlet.remote.model.search.SearchMisspellingsResponse;
import java.io.File;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import kotlin.Pair;
import kotlin.collections.C4930v;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.Charsets;
import okio.AbstractC5084a;
import okio.AbstractC5085b;
import okio.k;

/* loaded from: classes3.dex */
public final class b implements com.quizlet.qutils.image.capture.a, com.quizlet.remote.mapper.base.b, com.quizlet.remote.mapper.base.a {
    public final /* synthetic */ int a;

    public /* synthetic */ b(int i) {
        this.a = i;
    }

    public static k f(String str) {
        char c;
        int i;
        char cCharAt;
        char c2 = 'A';
        Intrinsics.checkNotNullParameter(str, "<this>");
        byte[] bArr = AbstractC5084a.a;
        Intrinsics.checkNotNullParameter(str, "<this>");
        int length = str.length();
        while (true) {
            c = '\t';
            if (length <= 0 || !((cCharAt = str.charAt(length - 1)) == '=' || cCharAt == '\n' || cCharAt == '\r' || cCharAt == ' ' || cCharAt == '\t')) {
                break;
            }
            length--;
        }
        int i2 = (int) ((length * 6) / 8);
        byte[] bArrCopyOf = new byte[i2];
        int i3 = 0;
        int i4 = 0;
        int i5 = 0;
        int i6 = 0;
        while (true) {
            if (i3 < length) {
                char cCharAt2 = str.charAt(i3);
                char c3 = c2;
                if (c2 <= cCharAt2 && cCharAt2 < '[') {
                    i = cCharAt2 - 'A';
                } else if ('a' <= cCharAt2 && cCharAt2 < '{') {
                    i = cCharAt2 - 'G';
                } else if ('0' <= cCharAt2 && cCharAt2 < ':') {
                    i = cCharAt2 + 4;
                } else if (cCharAt2 != '+' && cCharAt2 != '-') {
                    if (cCharAt2 != '/' && cCharAt2 != '_') {
                        if (cCharAt2 != '\n' && cCharAt2 != '\r' && cCharAt2 != ' ' && cCharAt2 != c) {
                            break;
                        }
                        i3++;
                        c2 = c3;
                        c = '\t';
                    } else {
                        i = 63;
                    }
                } else {
                    i = 62;
                }
                int i7 = i | (i5 << 6);
                i4++;
                if (i4 % 4 == 0) {
                    bArrCopyOf[i6] = (byte) (i7 >> 16);
                    int i8 = i6 + 2;
                    bArrCopyOf[i6 + 1] = (byte) (i7 >> 8);
                    i6 += 3;
                    bArrCopyOf[i8] = (byte) i7;
                }
                i5 = i7;
                i3++;
                c2 = c3;
                c = '\t';
            } else {
                int i9 = i4 % 4;
                if (i9 != 1) {
                    if (i9 == 2) {
                        bArrCopyOf[i6] = (byte) ((i5 << 12) >> 16);
                        i6 = 1 + i6;
                    } else if (i9 == 3) {
                        int i10 = i5 << 6;
                        int i11 = 1 + i6;
                        bArrCopyOf[i6] = (byte) (i10 >> 16);
                        i6 += 2;
                        bArrCopyOf[i11] = (byte) (i10 >> 8);
                    }
                    if (i6 != i2) {
                        bArrCopyOf = Arrays.copyOf(bArrCopyOf, i6);
                        Intrinsics.checkNotNullExpressionValue(bArrCopyOf, "copyOf(...)");
                    }
                }
            }
        }
        bArrCopyOf = null;
        if (bArrCopyOf != null) {
            return new k(bArrCopyOf);
        }
        return null;
    }

    public static k g(String str) {
        Intrinsics.checkNotNullParameter(str, "<this>");
        if (str.length() % 2 != 0) {
            throw new IllegalArgumentException("Unexpected hex string: ".concat(str).toString());
        }
        int length = str.length() / 2;
        byte[] bArr = new byte[length];
        for (int i = 0; i < length; i++) {
            int i2 = i * 2;
            bArr[i] = (byte) (okio.internal.b.a(str.charAt(i2 + 1)) + (okio.internal.b.a(str.charAt(i2)) << 4));
        }
        return new k(bArr);
    }

    public static k i(String str) {
        Intrinsics.checkNotNullParameter(str, "<this>");
        Intrinsics.checkNotNullParameter(str, "<this>");
        byte[] bytes = str.getBytes(Charsets.UTF_8);
        Intrinsics.checkNotNullExpressionValue(bytes, "getBytes(...)");
        k kVar = new k(bytes);
        kVar.c = str;
        return kVar;
    }

    public static boolean j(Context context) {
        e eVar;
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(context, "context");
        if (Build.VERSION.SDK_INT >= 30) {
            Object systemService = context.getSystemService("window");
            Intrinsics.e(systemService, "null cannot be cast to non-null type android.view.WindowManager");
            Rect bounds = ((WindowManager) systemService).getCurrentWindowMetrics().getBounds();
            Intrinsics.checkNotNullExpressionValue(bounds, "getBounds(...)");
            eVar = bounds.width() > bounds.height() ? e.c : e.b;
        } else {
            Point point = new Point();
            Object systemService2 = context.getSystemService("window");
            Intrinsics.e(systemService2, "null cannot be cast to non-null type android.view.WindowManager");
            ((WindowManager) systemService2).getDefaultDisplay().getSize(point);
            eVar = point.x > point.y ? e.c : e.b;
        }
        return eVar == e.c;
    }

    public static com.quizlet.data.model.search.a k(Pair remote) {
        Intrinsics.checkNotNullParameter(remote, "remote");
        SearchMisspellingsResponse searchMisspellingsResponse = (SearchMisspellingsResponse) remote.a;
        String str = (String) remote.b;
        String str2 = searchMisspellingsResponse.d;
        if (str2 == null) {
            str2 = "";
        }
        if (str2.length() != 0) {
            str = str2;
        }
        String str3 = searchMisspellingsResponse.e;
        if (str3 == null) {
            str3 = "";
        }
        Boolean bool = searchMisspellingsResponse.f;
        boolean zBooleanValue = bool != null ? bool.booleanValue() : false;
        String str4 = searchMisspellingsResponse.g;
        return new com.quizlet.data.model.search.a(str, str3, str4 != null ? str4 : "", zBooleanValue);
    }

    public static k l(int i, byte[] bArr) {
        Intrinsics.checkNotNullParameter(bArr, "<this>");
        Intrinsics.checkNotNullParameter(bArr, "<this>");
        if (i == -1234567890) {
            i = bArr.length;
        }
        AbstractC5085b.e(bArr.length, 0, i);
        return new k(C4930v.k(0, bArr, i));
    }

    @Override // com.quizlet.qutils.image.capture.a
    public File a(Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        return b(context, "png");
    }

    @Override // com.quizlet.qutils.image.capture.a
    public File b(Context context, String str) {
        Intrinsics.checkNotNullParameter(context, "context");
        if (str == null) {
            str = "png";
        }
        try {
            return t.b(g.e(context, "profileimages"), str);
        } catch (IOException e) {
            timber.log.c.a.e(e);
            return null;
        }
    }

    @Override // com.quizlet.remote.mapper.base.a
    public Object c(Object obj) {
        switch (this.a) {
            case 2:
                RemoteExercise remote = (RemoteExercise) obj;
                Intrinsics.checkNotNullParameter(remote, "remote");
                return new Exercise(remote.a, remote.b, remote.c, remote.d, remote.e);
            default:
                return k((Pair) obj);
        }
    }

    @Override // com.quizlet.qutils.image.capture.a
    public void d(Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        g.b(context, "profileimages");
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
        Exercise data = (Exercise) obj;
        Intrinsics.checkNotNullParameter(data, "data");
        return new RemoteExercise(data.a, data.b, data.c, data.d, data.e);
    }
}
