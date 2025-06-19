package io.ktor.http;

import androidx.compose.animation.core.J0;
import java.util.List;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;

/* loaded from: classes3.dex */
public final class l extends J0 {
    @Override // androidx.compose.animation.core.J0
    public final void O(String headerName) {
        Intrinsics.checkNotNullParameter(headerName, "name");
        super.O(headerName);
        List list = n.a;
        Intrinsics.checkNotNullParameter(headerName, "name");
        int i = 0;
        int i2 = 0;
        while (i < headerName.length()) {
            char cCharAt = headerName.charAt(i);
            int i3 = i2 + 1;
            if (Intrinsics.g(cCharAt, 32) <= 0 || StringsKt.F("\"(),/:;<=>?@[\\]{}", cCharAt, false)) {
                Intrinsics.checkNotNullParameter(headerName, "headerName");
                StringBuilder sbY = android.support.v4.media.session.a.y("Header name '", headerName, "' contains illegal character '");
                sbY.append(headerName.charAt(i2));
                sbY.append("' (code ");
                throw new IllegalHeaderNameException(android.support.v4.media.session.a.q(sbY, headerName.charAt(i2) & 255, ')'));
            }
            i++;
            i2 = i3;
        }
    }

    @Override // androidx.compose.animation.core.J0
    public final void P(String headerValue) {
        Intrinsics.checkNotNullParameter(headerValue, "value");
        super.P(headerValue);
        List list = n.a;
        Intrinsics.checkNotNullParameter(headerValue, "value");
        int i = 0;
        int i2 = 0;
        while (i < headerValue.length()) {
            char cCharAt = headerValue.charAt(i);
            int i3 = i2 + 1;
            if (Intrinsics.g(cCharAt, 32) < 0 && cCharAt != '\t') {
                Intrinsics.checkNotNullParameter(headerValue, "headerValue");
                StringBuilder sbY = android.support.v4.media.session.a.y("Header value '", headerValue, "' contains illegal character '");
                sbY.append(headerValue.charAt(i2));
                sbY.append("' (code ");
                throw new IllegalHeaderValueException(android.support.v4.media.session.a.q(sbY, headerValue.charAt(i2) & 255, ')'));
            }
            i++;
            i2 = i3;
        }
    }
}
