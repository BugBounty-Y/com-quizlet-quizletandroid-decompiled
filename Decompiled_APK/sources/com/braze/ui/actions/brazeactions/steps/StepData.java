package com.braze.ui.actions.brazeactions.steps;

import androidx.core.view.C;
import com.braze.enums.Channel;
import com.braze.models.outgoing.BrazeProperties;
import com.braze.support.BrazeLogger;
import com.braze.support.JsonUtils;
import com.braze.triggers.managers.h;
import com.braze.ui.actions.brazeactions.b;
import java.util.Iterator;
import java.util.List;
import java.util.Objects;
import kotlin.Metadata;
import kotlin.collections.CollectionsKt;
import kotlin.collections.J;
import kotlin.collections.K;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import kotlin.k;
import kotlin.l;
import kotlin.ranges.IntRange;
import kotlin.sequences.n;
import kotlin.sequences.q;
import org.jetbrains.annotations.NotNull;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

@Metadata
/* loaded from: classes.dex */
public final class StepData {

    @NotNull
    public static final Companion Companion = new Companion(null);

    @NotNull
    private final k args$delegate;

    @NotNull
    private final Channel channel;

    @NotNull
    private final k firstArg$delegate;

    @NotNull
    private final k secondArg$delegate;

    @NotNull
    private final JSONObject srcJson;

    @Metadata
    public static final class Companion {
        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        private Companion() {
        }
    }

    public StepData(@NotNull JSONObject srcJson, @NotNull Channel channel) {
        Intrinsics.checkNotNullParameter(srcJson, "srcJson");
        Intrinsics.checkNotNullParameter(channel, "channel");
        this.srcJson = srcJson;
        this.channel = channel;
        this.args$delegate = l.b(new b(3, this));
        this.firstArg$delegate = l.b(new b(4, this));
        this.secondArg$delegate = l.b(new b(5, this));
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final List args_delegate$lambda$0(StepData stepData) {
        Iterator c;
        final JSONArray jSONArrayOptJSONArray = stepData.srcJson.optJSONArray("args");
        if (jSONArrayOptJSONArray == null) {
            K.a.getClass();
            c = J.a;
        } else {
            c = new C(q.h(q.e(CollectionsKt.D(kotlin.ranges.l.h(0, jSONArrayOptJSONArray.length())), new Function1<Integer, Boolean>() { // from class: com.braze.ui.actions.brazeactions.steps.StepData$args_delegate$lambda$0$$inlined$iterator$1
                @Override // kotlin.jvm.functions.Function1
                public /* bridge */ /* synthetic */ Object invoke(Object obj) {
                    return invoke(((Number) obj).intValue());
                }

                public final Boolean invoke(int i) {
                    return Boolean.valueOf(Objects.nonNull(jSONArrayOptJSONArray.opt(i)));
                }
            }), new Function1<Integer, Object>() { // from class: com.braze.ui.actions.brazeactions.steps.StepData$args_delegate$lambda$0$$inlined$iterator$2
                public final Object invoke(int i) throws JSONException {
                    Object obj = jSONArrayOptJSONArray.get(i);
                    if (obj != null) {
                        return obj;
                    }
                    throw new NullPointerException("null cannot be cast to non-null type kotlin.Any");
                }

                @Override // kotlin.jvm.functions.Function1
                public /* bridge */ /* synthetic */ Object invoke(Object obj) {
                    return invoke(((Number) obj).intValue());
                }
            }));
        }
        return q.j(n.b(c));
    }

    public static /* synthetic */ StepData copy$default(StepData stepData, JSONObject jSONObject, Channel channel, int i, Object obj) {
        if ((i & 1) != 0) {
            jSONObject = stepData.srcJson;
        }
        if ((i & 2) != 0) {
            channel = stepData.channel;
        }
        return stepData.copy(jSONObject, channel);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final Object firstArg_delegate$lambda$1(StepData stepData) {
        return stepData.getArg$android_sdk_ui_release(0);
    }

    private final List<Object> getArgs() {
        return (List) this.args$delegate.getValue();
    }

    public static /* synthetic */ boolean isArgCountInBounds$default(StepData stepData, int i, IntRange intRange, int i2, Object obj) {
        if ((i2 & 1) != 0) {
            i = -1;
        }
        if ((i2 & 2) != 0) {
            intRange = null;
        }
        return stepData.isArgCountInBounds(i, intRange);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String isArgCountInBounds$lambda$3(int i, StepData stepData) {
        StringBuilder sbV = android.support.v4.media.session.a.v(i, "Expected ", " arguments. Got: ");
        sbV.append(stepData.getArgs());
        return sbV.toString();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String isArgCountInBounds$lambda$4(IntRange intRange, StepData stepData) {
        return "Expected " + intRange + " arguments. Got: " + stepData.getArgs();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String isArgOptionalJsonObject$lambda$6(int i, StepData stepData) {
        StringBuilder sbV = android.support.v4.media.session.a.v(i, "Argument [", "] is not a JSONObject. Source: ");
        sbV.append(stepData.srcJson);
        return sbV.toString();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String isArgString$lambda$5(int i, StepData stepData) {
        StringBuilder sbV = android.support.v4.media.session.a.v(i, "Argument [", "] is not a String. Source: ");
        sbV.append(stepData.srcJson);
        return sbV.toString();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final Object secondArg_delegate$lambda$2(StepData stepData) {
        return stepData.getArg$android_sdk_ui_release(1);
    }

    public final BrazeProperties coerceArgToPropertiesOrNull(int i) {
        Object objO = CollectionsKt.O(i, getArgs());
        if (objO == null || !(objO instanceof JSONObject)) {
            return null;
        }
        return new BrazeProperties((JSONObject) objO);
    }

    @NotNull
    public final StepData copy(@NotNull JSONObject srcJson, @NotNull Channel channel) {
        Intrinsics.checkNotNullParameter(srcJson, "srcJson");
        Intrinsics.checkNotNullParameter(channel, "channel");
        return new StepData(srcJson, channel);
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof StepData)) {
            return false;
        }
        StepData stepData = (StepData) obj;
        return Intrinsics.b(this.srcJson, stepData.srcJson) && this.channel == stepData.channel;
    }

    public final Object getArg$android_sdk_ui_release(int i) {
        return CollectionsKt.O(i, getArgs());
    }

    @NotNull
    public final Channel getChannel() {
        return this.channel;
    }

    public final Object getFirstArg() {
        return this.firstArg$delegate.getValue();
    }

    public final Object getSecondArg() {
        return this.secondArg$delegate.getValue();
    }

    @NotNull
    public final JSONObject getSrcJson() {
        return this.srcJson;
    }

    public int hashCode() {
        return this.channel.hashCode() + (this.srcJson.hashCode() * 31);
    }

    public final boolean isArgCountInBounds(int i, IntRange intRange) {
        if (i != -1 && getArgs().size() != i) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new a(i, this, 2), 7, (Object) null);
            return false;
        }
        if (intRange == null || intRange.b(getArgs().size())) {
            return true;
        }
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new h(5, intRange, this), 7, (Object) null);
        return false;
    }

    public final boolean isArgOptionalJsonObject(int i) {
        Object arg$android_sdk_ui_release = getArg$android_sdk_ui_release(i);
        if (arg$android_sdk_ui_release == null || (arg$android_sdk_ui_release instanceof JSONObject)) {
            return true;
        }
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new a(i, this, 1), 7, (Object) null);
        return false;
    }

    public final boolean isArgString(int i) {
        if (getArg$android_sdk_ui_release(i) instanceof String) {
            return true;
        }
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new a(i, this, 0), 7, (Object) null);
        return false;
    }

    @NotNull
    public String toString() {
        return "Channel " + this.channel + " and json\n" + JsonUtils.getPrettyPrintedString(this.srcJson);
    }

    public /* synthetic */ StepData(JSONObject jSONObject, Channel channel, int i, DefaultConstructorMarker defaultConstructorMarker) {
        this(jSONObject, (i & 2) != 0 ? Channel.UNKNOWN : channel);
    }
}
