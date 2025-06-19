package com.quizlet.quizletandroid.ui.common.ads.prebid.creators;

import android.content.Context;
import android.content.Intent;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3266t5;
import com.google.android.gms.internal.mlkit_vision_barcode.S;
import com.google.android.gms.internal.mlkit_vision_barcode.T;
import com.quizlet.data.model.C4133h1;
import com.quizlet.data.model.D0;
import com.quizlet.data.model.InterfaceC4176w0;
import com.quizlet.features.infra.models.studymodeshared.StudyableModelData;
import com.quizlet.generated.enums.A1;
import com.quizlet.quizletandroid.ui.studymodes.testmode.activities.TestStudyModeActivity;
import com.quizlet.remote.model.explanations.textbook.RemoteTextbook;
import com.quizlet.remote.model.qclass.RemoteClass;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.List;
import kotlin.jvm.internal.Intrinsics;
import okhttp3.internal.publicsuffix.PublicSuffixDatabase;

/* loaded from: classes3.dex */
public final class a implements com.quizlet.remote.mapper.base.a, com.quizlet.remote.mapper.base.b {
    public final /* synthetic */ int a;

    public /* synthetic */ a(int i) {
        this.a = i;
    }

    public static final String a(byte[] bArr, byte[][] bArr2, int i) {
        int i2;
        boolean z;
        int i3;
        int i4;
        int i5 = -1;
        byte[] bArr3 = PublicSuffixDatabase.e;
        int length = bArr.length;
        int i6 = 0;
        while (i6 < length) {
            int i7 = (i6 + length) / 2;
            while (i7 > i5 && bArr[i7] != 10) {
                i7 += i5;
            }
            int i8 = i7 + 1;
            int i9 = 1;
            while (true) {
                i2 = i8 + i9;
                if (bArr[i2] == 10) {
                    break;
                }
                i9++;
            }
            int i10 = i2 - i8;
            int i11 = i;
            boolean z2 = false;
            int i12 = 0;
            int i13 = 0;
            while (true) {
                if (z2) {
                    i3 = 46;
                    z = false;
                } else {
                    byte b = bArr2[i11][i12];
                    byte[] bArr4 = okhttp3.internal.b.a;
                    int i14 = b & 255;
                    z = z2;
                    i3 = i14;
                }
                byte b2 = bArr[i8 + i13];
                byte[] bArr5 = okhttp3.internal.b.a;
                i4 = i3 - (b2 & 255);
                if (i4 != 0) {
                    break;
                }
                i13++;
                i12++;
                if (i13 == i10) {
                    break;
                }
                if (bArr2[i11].length != i12) {
                    z2 = z;
                } else {
                    if (i11 == bArr2.length - 1) {
                        break;
                    }
                    i11++;
                    z2 = true;
                    i12 = -1;
                }
            }
            if (i4 >= 0) {
                if (i4 <= 0) {
                    int i15 = i10 - i13;
                    int length2 = bArr2[i11].length - i12;
                    int length3 = bArr2.length;
                    for (int i16 = i11 + 1; i16 < length3; i16++) {
                        length2 += bArr2[i16].length;
                    }
                    if (length2 >= i15) {
                        if (length2 <= i15) {
                            Charset UTF_8 = StandardCharsets.UTF_8;
                            Intrinsics.checkNotNullExpressionValue(UTF_8, "UTF_8");
                            return new String(bArr, i8, i10, UTF_8);
                        }
                    }
                    length = i7;
                }
                i6 = i2 + 1;
            } else {
                length = i7;
            }
            i5 = -1;
        }
        return null;
    }

    public static Intent b(Context context, int i, StudyableModelData studyableModelData, long j, boolean z, InterfaceC4176w0 testMeteredEvent, InterfaceC4176w0 learnMeteredEvent, boolean z2) {
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(studyableModelData, "studyableModelData");
        Intrinsics.checkNotNullParameter(testMeteredEvent, "testMeteredEvent");
        Intrinsics.checkNotNullParameter(learnMeteredEvent, "learnMeteredEvent");
        Intent intent = new Intent(context, (Class<?>) TestStudyModeActivity.class);
        AbstractC3266t5.c(intent, Integer.valueOf(i), studyableModelData, Long.valueOf(j), z, TestStudyModeActivity.v, A1.TEST.a(), null, null, 896);
        intent.putExtra("meteredEvent", testMeteredEvent);
        intent.putExtra("learnMeteredEvent", learnMeteredEvent);
        intent.putExtra("isFromNotes", z2);
        return intent;
    }

    public static C4133h1 d(RemoteClass remote) {
        Intrinsics.checkNotNullParameter(remote, "remote");
        return new C4133h1(remote.a, remote.b, remote.c, remote.d, remote.e, remote.f, remote.g, remote.h, remote.i, remote.j, remote.k, remote.l, remote.m);
    }

    @Override // com.quizlet.remote.mapper.base.a
    public Object c(Object obj) {
        switch (this.a) {
            case 2:
                RemoteTextbook remote = (RemoteTextbook) obj;
                Intrinsics.checkNotNullParameter(remote, "remote");
                long j = remote.a;
                String str = remote.c;
                String str2 = str == null ? "" : str;
                String str3 = remote.d;
                String str4 = str3 == null ? "" : str3;
                String str5 = remote.e;
                String str6 = str5 == null ? "" : str5;
                String str7 = remote.g;
                String str8 = str7 == null ? "" : str7;
                Boolean bool = remote.h;
                boolean zBooleanValue = bool != null ? bool.booleanValue() : false;
                Long l = remote.k;
                return new D0(j, remote.b, str2, str6, str8, zBooleanValue, l != null ? l.longValue() : 0L, remote.l, str4);
            default:
                return d((RemoteClass) obj);
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

    @Override // com.quizlet.remote.mapper.base.c
    public Object h(Object obj) throws Exception {
        C4133h1 data = (C4133h1) obj;
        Intrinsics.checkNotNullParameter(data, "data");
        throw new Exception("Not implemented");
    }
}
