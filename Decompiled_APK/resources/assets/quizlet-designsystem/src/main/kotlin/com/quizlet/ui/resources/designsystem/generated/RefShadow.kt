
// Do not edit directly
// See https://github.com/quizlet/quizlet-design-tokens for code generation


package com.quizlet.ui.resources.designsystem.generated

import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp

interface RefShadow {
    
    /** Shadow Spread of 0 */
    val refShadowSpreadNone: Dp
    
    /** Shadow Offset of 0 */
    val refShadowOffsetNone: Dp
    
    /** Shadow Offset of 2 */
    val refShadowOffsetSmall: Dp
    
    /** Shadow Offset of 4 */
    val refShadowOffsetMedium: Dp
    
    /** Shadow Blur of 4 */
    val refShadowBlurSmall: Dp
    
    /** Shadow Blur of 16 */
    val refShadowBlurMedium: Dp
    
    /** Shadow Blur of 32 */
    val refShadowBlurLarge: Dp

    companion object : RefShadow {
        override val refShadowSpreadNone = 0.dp
        override val refShadowOffsetNone = 0.dp
        override val refShadowOffsetSmall = 2.dp
        override val refShadowOffsetMedium = 4.dp
        override val refShadowBlurSmall = 4.dp
        override val refShadowBlurMedium = 16.dp
        override val refShadowBlurLarge = 32.dp
    }
}
