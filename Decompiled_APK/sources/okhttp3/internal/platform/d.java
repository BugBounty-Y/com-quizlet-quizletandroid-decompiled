package okhttp3.internal.platform;

import androidx.compose.runtime.C0814p;
import com.quizlet.data.model.C2;
import com.quizlet.generated.enums.EnumC4479f;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.ui.widgets.q;
import java.time.LocalDate;
import java.time.LocalDateTime;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public abstract class d {
    public static final /* synthetic */ int a = 0;

    public static final String a(C2 c2, C0814p c0814p) {
        Intrinsics.checkNotNullParameter(c2, "<this>");
        c0814p.X(1217064820);
        EnumC4479f enumC4479f = c2.b;
        Intrinsics.checkNotNullParameter(enumC4479f, "<this>");
        int i = q.a[enumC4479f.ordinal()];
        Integer numValueOf = i != 1 ? i != 2 ? null : Integer.valueOf(R.plurals.progressType_week) : Integer.valueOf(R.plurals.progressType_day);
        String strC = numValueOf != null ? com.quizlet.quizletandroid.ui.studymodes.assistant.settings.navigation.b.c(numValueOf.intValue(), c2.a, new Object[0], c0814p) : null;
        if (strC == null) {
            strC = "";
        }
        c0814p.p(false);
        return strC;
    }

    public static final boolean b(C2 c2) {
        Intrinsics.checkNotNullParameter(c2, "<this>");
        LocalDateTime localDateTime = c2.c;
        return Intrinsics.b(localDateTime != null ? localDateTime.toLocalDate() : null, LocalDate.now());
    }
}
