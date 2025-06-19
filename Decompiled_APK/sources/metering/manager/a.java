package metering.manager;

import androidx.compose.animation.core.J0;
import assistantMode.types.TestGeneratorOutputMetadata;
import assistantMode.types.test.GradedTestResult;
import assistantMode.types.test.Test;
import assistantMode.types.test.TestPaywall;
import com.quizlet.quizletandroid.ui.activitycenter.views.i;
import com.quizlet.shared.enums.h;
import java.util.LinkedHashMap;
import kotlin.NoWhenBranchMatchedException;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a extends J0 {
    public assistantMode.types.test.a T(assistantMode.types.test.a data) {
        Intrinsics.checkNotNullParameter(data, "data");
        Intrinsics.checkNotNullParameter(data, "data");
        h hVar = null;
        if (data instanceof GradedTestResult) {
            TestGeneratorOutputMetadata testGeneratorOutputMetadata = ((GradedTestResult) data).c;
            if (!testGeneratorOutputMetadata.a || testGeneratorOutputMetadata.b) {
                hVar = h.d;
            }
        } else if (!(data instanceof Test) && !(data instanceof TestPaywall)) {
            throw new NoWhenBranchMatchedException();
        }
        i iVar = (i) this.b;
        iVar.e(hVar);
        if (data instanceof Test) {
            TestGeneratorOutputMetadata testGeneratorOutputMetadata2 = ((Test) data).b;
            if ((!testGeneratorOutputMetadata2.a || testGeneratorOutputMetadata2.b) && iVar.c(h.d) && !(data instanceof TestPaywall)) {
                data = new TestPaywall(new TestGeneratorOutputMetadata(false, 7));
            }
        }
        data.getMetadata().c = (LinkedHashMap) iVar.b;
        return data;
    }
}
