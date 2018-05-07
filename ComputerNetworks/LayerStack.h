#ifndef __LAYERSTACK_H
#define __LAYERSTACK_H

#include "ILayerConstructor.h"
#include "MemBlock.h"

/// Layers in stack
#define LAYER_STACK_COUNT 7

/*
  LayerStack 
*/
class CN_DLLSPEC LayerStack
{
public:
    /// Constructor
    LayerStack()
    {
        memset(m_stack, NULL, sizeof(m_stack));
    }

    /// Sets constructor of specified layer
    void setLayer(uint8 layer, ILayerConstructor* layerConstructor)
    {
        if (layer && layer <= LAYER_STACK_COUNT)
        {
            m_stack[layer] = layerConstructor;

            if (layerConstructor)
            {
                layerConstructor->setLowerLayer(m_stack[layer - 1]);
                layerConstructor->setUpperLayer(m_stack[layer + 1]);
            }

            if (m_stack[layer - 1])
                m_stack[layer - 1]->setUpperLayer(layerConstructor);

            if (m_stack[layer + 1])
                m_stack[layer + 1]->setLowerLayer(layerConstructor);
        }
    }

    /// Constructs full packets, starts with topmost layer
    MemBlock* construct()
    {
        for (uint8 i = LAYER_STACK_COUNT; i >= 1; i--)
        {
            if (m_stack[i])
                return construct(i);
        }

        return NULL;
    }

    /// Constructs packet from specified layer
    MemBlock* construct(uint8 beginLayer)
    {
        MemBlock* memory = NULL;

        for (uint8 i = beginLayer; i >= 1; i--)
        {
            if (!m_stack[i])
                continue;

            MemBlock* lMemory = m_stack[i]->construct(memory);

            if (memory)
            {
                memory->prepend(lMemory);
                delete lMemory;
            }
            else
            {
                memory = lMemory;
            }
        }

        return memory;
    }

private:
    /// Stack of constructors
    ILayerConstructor* m_stack[LAYER_STACK_COUNT + 2];
};


#endif
