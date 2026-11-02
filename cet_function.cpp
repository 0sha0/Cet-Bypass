#include "cet_function.h"

namespace cethidden
{

Result CallFunction(const void* function, std::initializer_list<std::uint64_t> args)
{
    if (!function)
    {
        return {};
    }
    return RunHidden(reinterpret_cast<void*>(CetHiddenFunctionStart),
                     const_cast<void*>(function), 0, args.begin(), args.size());
}

} // namespace cethidden
