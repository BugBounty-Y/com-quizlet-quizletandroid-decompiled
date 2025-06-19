package com.braze.ui.actions;

import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import com.braze.enums.Channel;
import com.braze.support.BrazeLogger;
import com.braze.triggers.managers.i;
import com.braze.ui.activities.BrazeFeedActivity;
import kotlin.Metadata;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes.dex */
public class NewsfeedAction implements IAction {

    @NotNull
    private final Channel channel;
    private final Bundle extras;

    public NewsfeedAction(Bundle bundle, @NotNull Channel channel) {
        Intrinsics.checkNotNullParameter(channel, "channel");
        this.extras = bundle;
        this.channel = channel;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String execute$lambda$0() {
        return "BrazeFeedActivity was not opened successfully.";
    }

    @Override // com.braze.ui.actions.IAction
    public void execute(@NotNull Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        try {
            Intent intent = new Intent(context, (Class<?>) BrazeFeedActivity.class);
            Bundle bundle = this.extras;
            if (bundle != null) {
                intent.putExtras(bundle);
            }
            context.startActivity(intent);
        } catch (Exception e) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.E, (Throwable) e, false, (Function0) new i(22), 4, (Object) null);
        }
    }
}
