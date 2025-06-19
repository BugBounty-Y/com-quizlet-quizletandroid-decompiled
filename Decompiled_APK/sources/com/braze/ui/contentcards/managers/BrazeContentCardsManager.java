package com.braze.ui.contentcards.managers;

import com.braze.ui.contentcards.b;
import com.braze.ui.contentcards.listeners.DefaultContentCardsActionListener;
import com.braze.ui.contentcards.listeners.IContentCardsActionListener;
import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.k;
import kotlin.l;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes.dex */
public class BrazeContentCardsManager {

    @NotNull
    public static final Companion Companion = new Companion(null);

    @NotNull
    private static final k instance$delegate = l.b(new b(5));
    private IContentCardsActionListener contentCardsActionListener = new DefaultContentCardsActionListener();

    @Metadata
    public static final class Companion {
        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        @NotNull
        public final BrazeContentCardsManager getInstance() {
            return (BrazeContentCardsManager) BrazeContentCardsManager.instance$delegate.getValue();
        }

        private Companion() {
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final BrazeContentCardsManager instance_delegate$lambda$0() {
        return new BrazeContentCardsManager();
    }

    public final IContentCardsActionListener getContentCardsActionListener() {
        return this.contentCardsActionListener;
    }

    public final void setContentCardsActionListener(IContentCardsActionListener iContentCardsActionListener) {
        if (iContentCardsActionListener == null) {
            iContentCardsActionListener = new DefaultContentCardsActionListener();
        }
        this.contentCardsActionListener = iContentCardsActionListener;
    }
}
