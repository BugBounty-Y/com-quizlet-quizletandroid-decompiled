package com.braze.ui.actions.brazeactions.steps;

import android.content.Context;
import androidx.core.view.C;
import com.braze.ui.actions.brazeactions.BrazeActionParser;
import java.util.Iterator;
import kotlin.Metadata;
import kotlin.collections.CollectionsKt;
import kotlin.collections.J;
import kotlin.collections.K;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.ranges.l;
import kotlin.sequences.q;
import org.jetbrains.annotations.NotNull;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

@Metadata
/* loaded from: classes.dex */
public final class ContainerStep extends BaseBrazeActionStep {

    @NotNull
    public static final ContainerStep INSTANCE = new ContainerStep();

    private ContainerStep() {
        super(null);
    }

    public final Iterator getChildStepIterator$android_sdk_ui_release(StepData data) {
        Intrinsics.checkNotNullParameter(data, "data");
        final JSONArray jSONArray = data.getSrcJson().getJSONArray("steps");
        if (jSONArray != null) {
            return new C(q.h(q.e(CollectionsKt.D(l.h(0, jSONArray.length())), new Function1<Integer, Boolean>() { // from class: com.braze.ui.actions.brazeactions.steps.ContainerStep$getChildStepIterator$$inlined$iterator$1
                @Override // kotlin.jvm.functions.Function1
                public /* bridge */ /* synthetic */ Object invoke(Object obj) {
                    return invoke(((Number) obj).intValue());
                }

                public final Boolean invoke(int i) {
                    return Boolean.valueOf(jSONArray.opt(i) instanceof JSONObject);
                }
            }), new Function1<Integer, JSONObject>() { // from class: com.braze.ui.actions.brazeactions.steps.ContainerStep$getChildStepIterator$$inlined$iterator$2
                public final JSONObject invoke(int i) throws JSONException {
                    Object obj = jSONArray.get(i);
                    if (obj != null) {
                        return (JSONObject) obj;
                    }
                    throw new NullPointerException("null cannot be cast to non-null type org.json.JSONObject");
                }

                @Override // kotlin.jvm.functions.Function1
                public /* bridge */ /* synthetic */ Object invoke(Object obj) {
                    return invoke(((Number) obj).intValue());
                }
            }));
        }
        K.a.getClass();
        return J.a;
    }

    @Override // com.braze.ui.actions.brazeactions.steps.IBrazeActionStep
    public boolean isValid(@NotNull StepData data) {
        Intrinsics.checkNotNullParameter(data, "data");
        return data.getSrcJson().has("steps");
    }

    @Override // com.braze.ui.actions.brazeactions.steps.IBrazeActionStep
    public void run(@NotNull Context context, @NotNull StepData data) {
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(data, "data");
        Iterator childStepIterator$android_sdk_ui_release = getChildStepIterator$android_sdk_ui_release(data);
        while (childStepIterator$android_sdk_ui_release.hasNext()) {
            BrazeActionParser.INSTANCE.parse$android_sdk_ui_release(context, StepData.copy$default(data, (JSONObject) childStepIterator$android_sdk_ui_release.next(), null, 2, null));
        }
    }
}
