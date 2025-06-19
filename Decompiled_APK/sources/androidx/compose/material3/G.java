package androidx.compose.material3;

import androidx.compose.material3.internal.AbstractC0655t;
import androidx.compose.material3.internal.C0654s;
import androidx.compose.material3.internal.C0656u;
import androidx.compose.material3.internal.C0658w;
import androidx.compose.material3.tokens.AbstractC0727a;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.ui.text.C0995g;
import assistantMode.refactored.types.AssistantGradingSettings;
import assistantMode.refactored.types.StudiableData;
import assistantMode.refactored.types.StudySettings;
import assistantMode.types.aliases.ExperimentConfiguration;
import com.skydoves.balloon.internals.DefinitionKt;
import java.time.LocalDate;
import java.time.LocalTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Locale;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.ranges.IntRange;
import kotlin.text.StringsKt;

/* loaded from: classes.dex */
public final class G extends kotlin.jvm.internal.r implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;
    public final /* synthetic */ Object c;
    public final /* synthetic */ Object d;
    public final /* synthetic */ Object e;
    public final /* synthetic */ Object f;
    public final /* synthetic */ Object g;
    public final /* synthetic */ Object h;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public G(androidx.compose.ui.layout.W w, androidx.compose.ui.layout.M m, androidx.compose.ui.layout.W w2, androidx.compose.runtime.F0 f0, androidx.compose.runtime.F0 f02, androidx.compose.runtime.F0 f03, androidx.compose.runtime.F0 f04) {
        super(1);
        this.a = 0;
        this.b = w;
        this.d = m;
        this.c = w2;
        this.e = f0;
        this.f = f02;
        this.g = f03;
        this.h = f04;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        C0654s c0654s;
        switch (this.a) {
            case 0:
                androidx.compose.ui.layout.V v = (androidx.compose.ui.layout.V) obj;
                androidx.compose.ui.layout.W w = (androidx.compose.ui.layout.W) this.b;
                int i = w.a;
                float f = AbstractC0727a.b;
                androidx.compose.ui.layout.M m = (androidx.compose.ui.layout.M) this.d;
                boolean z = i > m.m0(f);
                float f2 = z ? H.b : H.d;
                float f3 = z ? H.c : H.d;
                androidx.compose.ui.layout.W w2 = (androidx.compose.ui.layout.W) this.c;
                androidx.compose.ui.layout.V.f(v, w2, 0, 0);
                int iM0 = w2.a - m.m0(f2);
                int iM02 = m.m0(f3) + (-w.b);
                float fI = ((androidx.compose.runtime.F0) this.e).i() + iM02;
                float fI2 = ((androidx.compose.runtime.F0) this.g).i() - ((((androidx.compose.runtime.F0) this.f).i() + iM0) + w.a);
                float fI3 = fI - ((androidx.compose.runtime.F0) this.h).i();
                if (fI2 < DefinitionKt.NO_Float_VALUE) {
                    iM0 += kotlin.math.c.b(fI2);
                }
                if (fI3 < DefinitionKt.NO_Float_VALUE) {
                    iM02 -= kotlin.math.c.b(fI3);
                }
                androidx.compose.ui.layout.V.f(v, w, iM0, iM02);
                return Unit.a;
            case 1:
                androidx.compose.ui.text.input.A a = (androidx.compose.ui.text.input.A) obj;
                int length = a.a.a.length();
                String str = ((C0658w) this.b).c;
                if (length <= str.length()) {
                    C0995g c0995g = a.a;
                    String str2 = c0995g.a;
                    int i2 = 0;
                    while (true) {
                        if (i2 >= str2.length()) {
                            ((InterfaceC0773a0) this.h).setValue(a);
                            String string = StringsKt.g0(c0995g.a).toString();
                            int length2 = string.length();
                            Function1 function1 = (Function1) this.d;
                            String str3 = "";
                            InterfaceC0773a0 interfaceC0773a0 = (InterfaceC0773a0) this.c;
                            Long lValueOf = null;
                            if (length2 != 0 && string.length() >= str.length()) {
                                ((C0656u) ((AbstractC0655t) this.e)).getClass();
                                try {
                                    LocalDate localDate = LocalDate.parse(string, DateTimeFormatter.ofPattern(str));
                                    c0654s = new C0654s(localDate.atTime(LocalTime.MIDNIGHT).atZone(C0656u.d).toInstant().toEpochMilli(), localDate.getYear(), localDate.getMonth().getValue(), localDate.getDayOfMonth());
                                } catch (DateTimeParseException unused) {
                                    c0654s = null;
                                }
                                C0693o0 c0693o0 = (C0693o0) this.f;
                                if (c0654s == null) {
                                    String upperCase = c0693o0.c.a.toUpperCase(Locale.ROOT);
                                    Intrinsics.checkNotNullExpressionValue(upperCase, "this as java.lang.String).toUpperCase(Locale.ROOT)");
                                    str3 = String.format(c0693o0.e, Arrays.copyOf(new Object[]{upperCase}, 1));
                                    Intrinsics.checkNotNullExpressionValue(str3, "format(this, *args)");
                                } else {
                                    IntRange intRange = c0693o0.a;
                                    int i3 = c0654s.a;
                                    if (intRange.b(i3)) {
                                        InterfaceC0764y3 interfaceC0764y3 = c0693o0.b;
                                        boolean zB = interfaceC0764y3.b(i3);
                                        long j = c0654s.d;
                                        if (!zB || !interfaceC0764y3.a(j)) {
                                            str3 = String.format(c0693o0.g, Arrays.copyOf(new Object[]{c0693o0.d.a(Long.valueOf(j), (Locale) this.g, false)}, 1));
                                            Intrinsics.checkNotNullExpressionValue(str3, "format(this, *args)");
                                        }
                                    } else {
                                        str3 = String.format(c0693o0.f, Arrays.copyOf(new Object[]{U.a(intRange.a), U.a(intRange.b)}, 2));
                                        Intrinsics.checkNotNullExpressionValue(str3, "format(this, *args)");
                                    }
                                }
                                interfaceC0773a0.setValue(str3);
                                if (((CharSequence) interfaceC0773a0.getValue()).length() == 0 && c0654s != null) {
                                    lValueOf = Long.valueOf(c0654s.d);
                                }
                                function1.invoke(lValueOf);
                            } else {
                                interfaceC0773a0.setValue("");
                                function1.invoke(null);
                            }
                        } else if (Character.isDigit(str2.charAt(i2))) {
                            i2++;
                        }
                    }
                }
                return Unit.a;
            default:
                assistantMode.types.y sequencingConfig = (assistantMode.types.y) obj;
                Intrinsics.checkNotNullParameter(sequencingConfig, "sequencingConfig");
                return new assistantMode.refactored.c((StudiableData) this.b, (ArrayList) this.c, (StudySettings) this.d, (AssistantGradingSettings) this.e, sequencingConfig, (ExperimentConfiguration) this.g, (Long) this.f, (HashMap) this.h);
        }
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ G(Object obj, Object obj2, Object obj3, Object obj4, Object obj5, Object obj6, Object obj7, int i) {
        super(1);
        this.a = i;
        this.b = obj;
        this.c = obj2;
        this.d = obj3;
        this.e = obj4;
        this.f = obj5;
        this.g = obj6;
        this.h = obj7;
    }
}
